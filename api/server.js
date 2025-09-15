// server.js (CommonJS) — reloga no Sankhya a cada requisição e filtra por CODVEND onde necessário
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const iconv = require('iconv-lite');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();

/* ===================== CONFIG ===================== */
const SANKHYA_URL = 'http://sankhya2.nxboats.com.br:8180';
const JWT_SECRET   = process.env.JWT_SECRET || 'mude-este-segredo';
const PORT         = process.env.PORT || 3000;

const ORIGINS = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS: Origin não permitida: ${origin}`));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

/* ===================== HTTP CLIENT SANKHYA ===================== */
const sankhya = axios.create({
  baseURL: SANKHYA_URL,
  timeout: 20000,
  headers: { 'Content-Type': 'application/json' },
  responseType: 'arraybuffer',
  transformResponse: [(data, headers) => {
    const ctype = headers?.['content-type'] || '';
    const isLatin1 = /charset=(iso-8859-1|latin1)/i.test(ctype);
    const buf = Buffer.from(data);
    const str = iconv.decode(buf, isLatin1 ? 'latin1' : 'utf8');
    try { return JSON.parse(str); } catch { return str; }
  }],
  validateStatus: () => true,
});

/* ===================== UTILS ===================== */
const toSQLSafe = (s) => String(s || '').replace(/'/g, "''");

function toBRDate(s) {
  const str = String(s || '').trim();
  if (!str) return null;
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(str)) return str;         // dd/mm/aaaa
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) {                      // aaaa-mm-dd
    const [y, m, d] = str.split('-');
    return `${d}/${m}/${y}`;
  }
  return null;
}

/* ===================== LOGIN SEMPRE FRESCO ===================== */
async function sankhyaLogin(usuario, senha) {
  const url = `${SANKHYA_URL}/mge/service.sbr?serviceName=MobileLoginSP.login&outputType=json`;
  const payload = {
    serviceName: "MobileLoginSP.login",
    requestBody: {
      NOMUSU: { "$": String(usuario).toUpperCase() },
      INTERNO: { "$": String(senha) },
      KEEPCONNECTED: { "$": "S" }
    }
  };
  const r = await sankhya.post(url, payload);
  if (r.status >= 400) throw new Error(`HTTP ${r.status}`);
  const jsessionid = r.data?.responseBody?.jsessionid?.["$"];
  if (!jsessionid) throw new Error('Login inválido (sem JSESSIONID)');
  return jsessionid;
}

async function sankhyaQuery(jsessionid, sql) {
  const url = `${SANKHYA_URL}/mge/service.sbr?serviceName=DbExplorerSP.executeQuery&outputType=json`;
  const payload = { serviceName: "DbExplorerSP.executeQuery", requestBody: { sql, outputType: "json" } };
  const r = await sankhya.post(url, payload, { headers: { Cookie: `JSESSIONID=${jsessionid}` }});
  if (r.status >= 400) throw new Error(`HTTP ${r.status}`);
  const rows = r.data?.responseBody?.rows || r.data?.responseBody?.resultSet?.rows || [];
  return rows;
}

async function sankhyaExecUpdate(jsessionid, sql) {
  const url = `${SANKHYA_URL}/mge/service.sbr?serviceName=DbExplorerSP.executeUpdate&outputType=json`;
  const payload = { serviceName: "DbExplorerSP.executeUpdate", requestBody: { sql, outputType: "json" } };
  const r = await sankhya.post(url, payload, { headers: { Cookie: `JSESSIONID=${jsessionid}` } });
  if (r.status >= 400) throw new Error(`HTTP ${r.status}`);
  const body = r.data?.responseBody || {};
  const updated = body.rowsAffected ?? body.rowsUpdated ?? body.updateCount ?? body.linhasAfetadas ?? null;
  return { raw: r.data, updated };
}

async function sankhyaDatasetSave(jsessionid, params) {
  const {
    entity, fields, pk = null, fk = null, values, crudListener = null,
  } = params || {};

  if (!entity || !Array.isArray(fields) || !values) {
    throw new Error("Parâmetros inválidos: 'entity', 'fields[]' e 'values' são obrigatórios.");
  }

  const payload = {
    serviceName: "DatasetSP.save",
    requestBody: {
      ...(crudListener ? { crudListener } : {}),
      entityName: entity,
      fields,
      records: [
        { ...(pk ? { pk } : {}), ...(fk ? { foreignKey: fk } : {}), values },
      ],
    },
  };

  const url = `${SANKHYA_URL}/mge/service.sbr?serviceName=DatasetSP.save&application=DynaformLauncher&outputType=json`;
  const r = await sankhya.post(url, payload, { headers: { Cookie: `JSESSIONID=${jsessionid}` } });
  if (r.status >= 400) throw new Error(`HTTP ${r.status}`);

  return {
    STATUS: r.data?.status,
    REQUISICAO: payload,
    RETORNO: r.data,
  };
}

/* ===================== AUTH (JWT) ===================== */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ erro: 'Token ausente' });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { usuario, senha, codvend, codusu, name }
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

/* ===================== LOGIN/LOGOUT ===================== */
app.post('/api/auth/login', async (req, res) => {
  try {
    let { usuario, senha } = req.body || {};
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios.' });

    const u = String(usuario).trim().toUpperCase();
    const js = await sankhyaLogin(u, senha);

    // Busca CODVEND/CODUSU/NOME
    const safeUser = toSQLSafe(u);
    const userRows = await sankhyaQuery(js, `
      SELECT CODUSU, NVL(CODVEND,0) AS CODVEND, NOMEUSU
        FROM TSIUSU
       WHERE UPPER(NOMEUSU) = '${safeUser}'
    `);
    const [codusu, codvend, nomeusu] = userRows[0] || [null, 0, u];
    const name = nomeusu || u;

    // Gera JWT com as infos necessárias
    const token = jwt.sign({ usuario: u, senha, codvend: Number(codvend||0), codusu, name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, usuario: u, codvend: Number(codvend||0), name });
  } catch (err) {
    console.error('Falha login:', err?.response?.data || err.message || SANKHYA_URL);
    res.status(401).json({ erro: 'Falha no login' });
  }
});

app.post('/api/auth/logout', auth, (req, res) => {
  res.json({ ok: true });
});

/* ===================== PEDIDOS ===================== */
// GET /api/pedidos (lista)
app.get('/api/pedidos', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const { ini, fim, fornecedor } = req.query || {};
    const like = (s) => String(s || '').toUpperCase().replace(/'/g, "''");

    const filtros = [
      `PEDI.TIPMOV = 'O'`,
      `ITE.PENDENTE = 'S'`,
      `PEDI.STATUSNOTA IN ( 'L' , 'A' , 'P') `,
      `PEDI.CODTIPOPER <> 4`,
      `PAR.CODVEND = ${Number(codvend||0)}`,
    ];
    if (ini && fim) {
      filtros.push(`TRUNC(PEDI.DTNEG) BETWEEN TO_DATE('${ini}','DD/MM/YYYY') AND TO_DATE('${fim}','DD/MM/YYYY')`);
    }
    if (fornecedor) {
      filtros.push(`UPPER(PAR.NOMEPARC) LIKE '%${like(fornecedor)}%'`);
    }

    const where = filtros.join(' AND ');
    const sql = `
SELECT
  PEDI.NUNOTA,
  PAR.NOMEPARC,
  SUM(ITE.VLRUNIT * (ITE.QTDNEG - ITE.QTDENTREGUE)) AS VLRPEDI,
  TO_CHAR(PEDI.DTNEG, 'YYYY-MM-DD"T"HH24:MI:SS')       AS DTNEG_ISO,
  PEDI.VLRNOTA,
  TO_CHAR(PEDI.DTPREVENT, 'YYYY-MM-DD"T"HH24:MI:SS')   AS DTPREVENT_ISO,
  CASE
    WHEN PEDI.DTPREVENT IS NULL THEN 'SEM PREVISÃO'
    WHEN PEDI.DTPREVENT - SYSDATE < 0 THEN 'ATRASADO'
    ELSE 'PLANEJADO'
  END AS STATUS,
  case when nvl(AD_STATUSPED,'1') ='1' then 'Pedido em aprovação'
when nvl(PEDI.AD_STATUSPED,'1') ='2' then 'Em Produção'
when nvl(PEDI.AD_STATUSPED,'1') ='3' then 'Aguardando embarque'
when nvl(PEDI.AD_STATUSPED,'1') ='4' then 'Em Transito'
when nvl(PEDI.AD_STATUSPED,'1') ='5' then 'Aguardando Liberação'
when nvl(PEDI.AD_STATUSPED,'1') ='6' then 'Desembaraçado'
when nvl(PEDI.AD_STATUSPED,'1') ='7' then 'Recebido'
when nvl(PEDI.AD_STATUSPED,'1') ='8' then 'Perdimento/Avaria'
when nvl(PEDI.AD_STATUSPED,'1') ='9' then 'Cancelado' end AS STATUSPED
, CASE 
WHEN MAX(REPROVADO) = 'S' THEN 'REPROVADO'
WHEN MAX(LIB.VLRLIBERADO) = 0 THEN 'EM DIRETORIA'
WHEN NVL(MAX(LIB.VLRLIBERADO),-1) = -1 THEN 'EM GERENCIA'
WHEN NVL(MAX(LIB.VLRLIBERADO),-1) > 0 AND MAX(REPROVADO) = 'N' THEN 'APROVADO'

 END AS STATUSLIB,
 MAX(OBSLIB) AS OBSREPROVADO

FROM TGFCAB PEDI
JOIN TGFITE ITE ON ITE.NUNOTA = PEDI.NUNOTA
JOIN TGFPAR PAR ON PAR.CODPARC = PEDI.CODPARC
LEFT JOIN TSILIB LIB ON LIB.NUCHAVE = PEDI.NUNOTA AND LIB.EVENTO = 1009
WHERE ${where}
GROUP BY PEDI.NUNOTA, PAR.NOMEPARC, PEDI.DTNEG, PEDI.VLRNOTA, PEDI.DTPREVENT , PEDI.AD_STATUSPED
ORDER BY 3 DESC
    `.trim();

    const rows = await sankhyaQuery(js, sql);
    const itens = rows.map(r => ({
      nunota: Number(r[0]),
      fornecedor: String(r[1] ?? '').trim(),
      vlrpedi: Number(r[2] ?? 0),
      dtneg: r[3] || null,
      vlrnota: Number(r[4] ?? 0),
      dtprevent: r[5] || null,
      status: String(r[6] ?? '').trim(),
      statusped: String(r[7] ?? '').trim(),
      statuslib: String(r[8] ?? '').trim(),
      obsreprovado: String(r[9] ?? '').trim(),
    }));

    res.json({ items: itens });
  } catch (err) {
    console.error('Erro /api/pedidos:', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao consultar pedidos' });
  }
});

// DETALHE DO PEDIDO — cabeçalho + itens pendentes
app.get('/api/pedidos/:nunota', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const nunota = Number(req.params.nunota);
    if (!nunota) return res.status(400).json({ erro: 'NUNOTA inválido' });

    const sqlHeader = `
SELECT
  CAB.NUNOTA,
  PAR.NOMEPARC,
  TO_CHAR(CAB.DTNEG,    'YYYY-MM-DD"T"HH24:MI:SS') AS DTNEG_ISO,
  TO_CHAR(CAB.DTPREVENT,'YYYY-MM-DD"T"HH24:MI:SS') AS DTPREVENT_ISO,
  CAB.VLRNOTA
FROM TGFCAB CAB
JOIN TGFPAR PAR ON PAR.CODPARC = CAB.CODPARC
WHERE CAB.NUNOTA = ${nunota}
  AND PAR.CODVEND = ${Number(codvend||0)}
`.trim();

    const hRows = await sankhyaQuery(js, sqlHeader);
    if (!hRows.length) {
      return res.status(404).json({ erro: 'Pedido não encontrado para este vendedor' });
    }

    const header = {
      nunota: Number(hRows[0][0]),
      fornecedor: String(hRows[0][1] ?? '').trim(),
      dtneg: hRows[0][2] || null,
      dtprevent: hRows[0][3] || null,
      vlrnota: Number(hRows[0][4] ?? 0),
    };

    const sqlItems = `
SELECT
  ITE.NUNOTA,
  ITE.SEQUENCIA,
  ITE.CODPROD,
  PRO.DESCRPROD,
  PRO.CODVOL,
  (ITE.QTDNEG - ITE.QTDENTREGUE) AS QTD,
  (ITE.VLRUNIT * (ITE.QTDNEG - ITE.QTDENTREGUE)) AS VLRPEDI,
  ITE.VLRUNIT
FROM TGFCAB PEDI
JOIN TGFITE ITE ON ITE.NUNOTA = PEDI.NUNOTA
JOIN TGFPRO PRO ON PRO.CODPROD = ITE.CODPROD
JOIN TGFPAR PAR ON PAR.CODPARC = PEDI.CODPARC
WHERE PEDI.TIPMOV = 'O'
  AND ITE.PENDENTE = 'S'
  AND PEDI.CODTIPOPER <> 4
  AND PAR.CODVEND = ${Number(codvend||0)}
  AND PEDI.NUNOTA = ${nunota}
ORDER BY 2 ASC
`.trim();

    const iRows = await sankhyaQuery(js, sqlItems);
    const items = iRows.map(r => ({
      nunota: Number(r[0]),
      sequencia: Number(r[1]),
      codprod: Number(r[2]),
      descrprod: String(r[3] ?? '').trim(),
      codvol: String(r[4] ?? '').trim(),
      qtd: Number(r[5] ?? 0),
      vlrpedi: Number(r[6] ?? 0),
      vlrunit: Number(r[7] ?? 0),
    }));

    return res.json({ header, items });
  } catch (err) {
    console.error('Erro /api/pedidos/:nunota', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao buscar detalhe do pedido' });
  }
});

// Alterar data de previsão (com validação e confirmação)
app.post('/api/pedidos/:nunota/previsao', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const nunota  = Number(req.params.nunota);
    let data      = String(req.body?.data || '').trim(); // dd/mm/aaaa ou aaaa-mm-dd
    if (!nunota || !data) return res.status(400).json({ erro: 'Parâmetros inválidos (nunota, data).' });

    if (/^\d{4}-\d{2}-\d{2}$/.test(data)) {
      const [y, m, d] = data.split('-'); data = `${d}/${m}/${y}`;
    }
    if (!/^\d{2}\/\d{2}\/\d{4}$/.test(data)) return res.status(400).json({ erro: 'Data inválida. Use dd/mm/aaaa.' });
    const [dd, mm, yyyy] = data.split('/').map(Number);
    const dt = new Date(yyyy, mm - 1, dd);
    const valid = dt.getFullYear() === yyyy && dt.getMonth() === (mm - 1) && dt.getDate() === dd;
    if (!valid) return res.status(400).json({ erro: 'Data inválida.' });

    const updSql = `
      UPDATE TGFCAB CAB
         SET CAB.DTPREVENT = TO_DATE('${data}','DD/MM/RRRR')
       WHERE CAB.NUNOTA = ${nunota}
         AND EXISTS (
               SELECT 1
                 FROM TGFPAR PAR
                WHERE PAR.CODPARC = CAB.CODPARC
                  AND PAR.CODVEND = ${Number(codvend||0)}
             )
    `;
    const { updated } = await sankhyaExecUpdate(js, updSql);
    if (!updated) return res.status(409).json({ erro: 'Nenhuma linha atualizada. Verifique permissões/filtros.' });

    const readSql = `SELECT TO_CHAR(CAB.DTPREVENT, 'YYYY-MM-DD"T"HH24:MI:SS') FROM TGFCAB CAB WHERE CAB.NUNOTA = ${nunota}`;
    const rows = await sankhyaQuery(js, readSql);
    const iso = rows?.[0]?.[0] || `${yyyy}-${String(mm).padStart(2,'0')}-${String(dd).padStart(2,'0')}T00:00:00`;

    return res.json({ ok: true, nunota, dataBR: data, dataISO: iso, linhasAfetadas: updated ?? undefined });
  } catch (err) {
    console.error('Erro /api/pedidos/:nunota/previsao:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao alterar data de previsão' });
  }
});

// Imprimir pedido (PDF)
app.post('/api/pedidos/:nunota/print', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const nunota = Number(req.params.nunota);
    if (!nunota) return res.status(400).json({ erro: 'NUNOTA inválido' });

    const RFE = String(req.body?.rfe || process.env.SANKHYA_RFE_PEDIDO || '1');
    const payload = {
      serviceName: "VisualizadorRelatorios.visualizarRelatorio",
      requestBody: {
        relatorio: {
          nuRfe: RFE,
          isApp: "N",
          nuApp: 1,
          parametros: { parametro: [{ classe: "java.math.BigDecimal", nome: "NUNOTA", valor: nunota }] }
        }
      }
    };

    const gen = await sankhya.post(
      '/mge/service.sbr?serviceName=VisualizadorRelatorios.visualizarRelatorio&outputType=json',
      payload,
      { headers: { Cookie: `JSESSIONID=${js}` } }
    );

    const chaveArquivo =
      gen.data?.responseBody?.chave?.valor ||
      gen.data?.responseBody?.chave?.["$"] ||
      gen.data?.responseBody?.chaveArquivo?.valor;

    if (!chaveArquivo) {
      console.error('Resposta gerarRelatorio sem chave:', gen.data);
      return res.status(500).json({ erro: "Falha ao obter chave do relatório" });
    }

    const dl = await axios.get(
      `${SANKHYA_URL}/mge/visualizadorArquivos.mge?hidemail=S&download=S&chaveArquivo=${encodeURIComponent(chaveArquivo)}`,
      {
        headers: { Cookie: `JSESSIONID=${js}` },
        responseType: 'arraybuffer',
        transformResponse: [(d) => d],
        validateStatus: () => true
      }
    );

    if (dl.status >= 400) return res.status(500).json({ erro: `Falha no download do PDF (HTTP ${dl.status})` });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="pedido_${nunota}.pdf"`);
    return res.send(dl.data);
  } catch (err) {
    console.error('Erro imprimir pedido:', err?.response?.data || err.message);
    return res.status(500).json({ erro: "Erro ao gerar/baixar relatório" });
  }
});

/* ===================== PRODUTOS CRÍTICOS ===================== */
app.get('/api/produtos-criticos', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const dias = Number(req.query?.dias ?? 30);
    const fornecedor = String(req.query?.fornecedor || '').trim().toUpperCase();
    const filtroFornecedor = fornecedor
      ? `AND UPPER(PAR.NOMEPARC) LIKE '%${fornecedor.replace(/'/g, "''")}%'`
      : '';

    const sql = `
SELECT 
    PAR.CODPARC,
    PAR.NOMEPARC,
    COUNT(COM.CODPROD) AS QTDPROD,
    MAX(COM.LEADTIME) AS LEADTIME,
    ROUND( (COUNT(COM.CODPROD) * 100.0) / SUM(COUNT(COM.CODPROD)) OVER (), 2 ) AS PERCENTUAL
FROM AD_TGFPROCOM COM
JOIN TGFPAR PAR ON PAR.CODPARC = COM.CODPARC
WHERE COM.CODVEND = ${Number(codvend||0)}
  AND COM.NECESSIDADE > 0
  AND COM.DTRUTURA <= SYSDATE + ${dias}
  ${filtroFornecedor}
GROUP BY PAR.CODPARC, PAR.NOMEPARC
ORDER BY QTDPROD DESC
`.trim();

    const rows = await sankhyaQuery(js, sql);
    const items = rows.map(r => ({
      codparc: Number(r[0]),
      fornecedor: String(r[1] ?? '').trim(),
      qtdprod: Number(r[2] ?? 0),
      leadtime: Number(r[3] ?? 0),
      percentual: Number(r[4] ?? 0),
    }));
    res.json({ items });
  } catch (err) {
    console.error('GET /api/produtos-criticos', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao listar produtos críticos' });
  }
});

app.get('/api/produtos-criticos/:codparc', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const codparc = Number(req.params.codparc);
    const dias = Number(req.query?.dias ?? 5);
    if (!codparc) return res.status(400).json({ erro: 'Parâmetros inválidos' });

    const sql = `
SELECT
  PAR.CODPARC,
  PAR.NOMEPARC,
  COM.CODPROD,
  PRO.DESCRPROD,
  PRO.CODVOL,
  NVL(COM.LEADTIME,0) AS LEADTIME,
  COM.ESTOQUE,
  COM.EMPENHO,
  COM.COMPRAPEN,
  COM.NECESSIDADE,
  ROUND(COM.GIRODIARIO,2) AS GIROMENSAL,
  TO_CHAR(COM.DTMELHORPED, 'YYYY-MM-DD"T"HH24:MI:SS') AS DTMELHORPED_ISO, 
  SNK_GET_CUSTO('REPOSICAO',1,COM.CODPROD,0,'',SYSDATE) AS PRECO

    FROM AD_TGFPROCOM COM
    JOIN TGFPAR PAR ON PAR.CODPARC = COM.CODPARC
    JOIN TGFPRO PRO ON PRO.CODPROD = COM.CODPROD
    WHERE COM.CODVEND = ${Number(codvend||0)}
      AND COM.CODPARC = ${codparc}
      AND COM.DTMELHORPED <= SYSDATE - ${dias}
      AND COM.NECESSIDADE > 0
    ORDER BY PRO.DESCRPROD ASC
`.trim();

    const rows = await sankhyaQuery(js, sql);

    let fornecedor = { codparc, nomeparc: "" };
    const items = rows.map(r => {
      fornecedor = { codparc: Number(r[0]), nomeparc: String(r[1] ?? '').trim() };
      return {
        codprod: Number(r[2]),
        descrprod: String(r[3] ?? '').trim(),
        codvol: String(r[4] ?? '').trim(),
        leadtime: Number(r[5] ?? 0),
        estoque: Number(r[6] ?? 0),
        empenho: Number(r[7] ?? 0),
        comprapen: Number(r[8] ?? 0),
        necessidade: Number(r[9] ?? 0),
        giromensal: Number(r[10] ?? 0),
        dtmelhorped: r[11] || null,
        preco: Number(r[12] ?? 0),
        sugestaoQtd: Number(r[9] ?? 0),
      };
    });

    if (!rows.length) {
      const nome = await sankhyaQuery(js, `SELECT NOMEPARC FROM TGFPAR WHERE CODPARC=${codparc}`);
      fornecedor.nomeparc = String(nome?.[0]?.[0] || '').trim();
    }

    res.json({ fornecedor, items });
  } catch (err) {
    console.error('GET /api/produtos-criticos/:codparc', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao listar produtos do fornecedor' });
  }
});

/* ===================== DIVERGÊNCIAS ===================== */
app.get('/api/divergencias', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const ini = String(req.query?.ini || '').trim();
    const fim = String(req.query?.fim || '').trim();
    const fornecedor = String(req.query?.fornecedor || '').trim().toUpperCase();
    const statusTxt = String(req.query?.status || '').trim();

    const filtros = [
      `PAR.CODVEND = ${Number(codvend||0)}`,
    ];
    if (ini && fim) {
      filtros.push(`TRUNC(REG.DTNEG) BETWEEN TO_DATE('${toSQLSafe(ini)}','DD/MM/YYYY') AND TO_DATE('${toSQLSafe(fim)}','DD/MM/YYYY')`);
    }
    if (fornecedor) {
      filtros.push(`UPPER(PAR.NOMEPARC) LIKE '%${toSQLSafe(fornecedor)}%'`);
    }
    if (statusTxt) {
      filtros.push(`F_DESCROPC('AD_REGISTROAVARIA','STATUS', REG.STATUS) = '${toSQLSafe(statusTxt)}'`);
    }
    const where = `WHERE ${filtros.join(' AND ')}`;

    const sql = `
SELECT 
  PAR.CODPARC,
  PAR.NOMEPARC,
  COUNT(DISTINCT REG.CODAVARIA) AS QTD_OCORR,
  COUNT(*) AS QTD_ITENS,
  SUM(ITE.QTDNEG * ITE.VLRUNIT) AS VLRTOT,
  TO_CHAR(MAX(REG.DTNEG), 'YYYY-MM-DD"T"HH24:MI:SS') AS DTNEG_MAX_ISO,
  ROUND( (COUNT(DISTINCT REG.CODAVARIA) * 100.0) / SUM(COUNT(DISTINCT REG.CODAVARIA)) OVER (), 2 ) AS PERCENTUAL
FROM AD_REGISTROAVARIA REG
JOIN AD_ITENSAVARIA ITE ON ITE.CODAVARIA = REG.CODAVARIA
JOIN TGFPAR PAR ON PAR.CODPARC = REG.CODPARC
${where}
GROUP BY PAR.CODPARC, PAR.NOMEPARC
ORDER BY VLRTOT DESC
`.trim();

    const rows = await sankhyaQuery(js, sql);
    const items = rows.map(r => ({
      codparc: Number(r[0]),
      fornecedor: String(r[1] ?? '').trim(),
      qtdOcorr: Number(r[2] ?? 0),
      qtdItens: Number(r[3] ?? 0),
      vlrTot: Number(r[4] ?? 0),
      dtnegMax: r[5] || null,
      percentual: Number(r[6] ?? 0),
    }));

    res.json({ items });
  } catch (err) {
    console.error('GET /api/divergencias', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao listar divergências' });
  }
});

app.get('/api/divergencias/:codparc', auth, async (req, res) => {
  try {
    const { usuario, senha, codvend } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const codparc = Number(req.params.codparc);
    const ini = String(req.query?.ini || '').trim();
    const fim = String(req.query?.fim || '').trim();
    const statusTxt = String(req.query?.status || '').trim();

    if (!codparc) return res.status(400).json({ erro: 'Parâmetros inválidos' });

    const filtros = [
      `PAR.CODVEND = ${Number(codvend||0)}`,
      `REG.CODPARC = ${codparc}`,
    ];
    if (ini && fim) {
      filtros.push(`TRUNC(REG.DTNEG) BETWEEN TO_DATE('${toSQLSafe(ini)}','DD/MM/YYYY') AND TO_DATE('${toSQLSafe(fim)}','DD/MM/YYYY')`);
    }
    if (statusTxt) {
      filtros.push(`F_DESCROPC('AD_REGISTROAVARIA','STATUS', REG.STATUS) = '${toSQLSafe(statusTxt)}'`);
    }
    const where = `WHERE ${filtros.join(' AND ')}`;

    const sql = `
SELECT 
  REG.CODAVARIA,
  REG.NUNOTA,
  TO_CHAR(REG.DTNEG, 'YYYY-MM-DD"T"HH24:MI:SS') AS DTNEG_ISO,
  F_DESCROPC('AD_REGISTROAVARIA','STATUS', REG.STATUS) AS STATUS_TXT,
  ITE.SEQUENCIA,
  ITE.CODPROD,
  PRO.DESCRPROD,
  PRO.CODVOL,
  ITE.QTDNEG,
  ITE.VLRUNIT,
  (ITE.QTDNEG * ITE.VLRUNIT) AS VLRTOT,
  F_DESCROPC('AD_ITENSAVARIA','OCORRENCIA', ITE.OCORRENCIA) AS OCORRENCIA_TXT
FROM AD_REGISTROAVARIA REG
JOIN AD_ITENSAVARIA ITE ON ITE.CODAVARIA = REG.CODAVARIA
JOIN TGFPRO PRO ON PRO.CODPROD = ITE.CODPROD
JOIN TGFPAR PAR ON PAR.CODPARC = REG.CODPARC
${where}
ORDER BY REG.CODAVARIA DESC, ITE.SEQUENCIA ASC
`.trim();

    const rows = await sankhyaQuery(js, sql);

    const nome = await sankhyaQuery(js, `SELECT NOMEPARC FROM TGFPAR WHERE CODPARC=${codparc}`);
    const fornecedor = { codparc, nomeparc: String(nome?.[0]?.[0] || '').trim() };

    const items = rows.map(r => ({
      codavaria: Number(r[0]),
      nunota: Number(r[1]),
      dtneg: r[2] || null,
      status: String(r[3] ?? '').trim(),
      sequencia: Number(r[4]),
      codprod: Number(r[5]),
      descrprod: String(r[6] ?? '').trim(),
      codvol: String(r[7] ?? '').trim(),
      qtdneg: Number(r[8] ?? 0),
      vlrunit: Number(r[9] ?? 0),
      vlrtot: Number(r[10] ?? 0),
      ocorrencia: String(r[11] ?? '').trim(),
    }));

    res.json({ fornecedor, items });
  } catch (err) {
    console.error('GET /api/divergencias/:codparc', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao listar ocorrências do fornecedor' });
  }
});

/* ===================== AI SUPRIMENTOS ===================== */
const genAIKey = 'AIzaSyCOTFRIHQLZTkspuzy1wAiiVOJcy_-ON2M';
const genAI = genAIKey ? new GoogleGenerativeAI(genAIKey) : null;

app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    if (!genAI) return res.status(500).json({ erro: 'GOOGLE_API_KEY não configurada no .env' });

    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const {
      message = '',
      safetyDays = 5,
      top = 30,
      fornecedor = '',
      grupo = ''
    } = req.body || {};

    const filtroFornecedor = fornecedor
      ? `AND UPPER(PAR.NOMEPARC) LIKE '%${String(fornecedor).toUpperCase().replace(/'/g,"''")}%'`
      : '';
    const filtroGrupo = grupo
      ? `AND (UPPER(NVL(GRU.DESCRGRU,'')) LIKE '%${String(grupo).toUpperCase().replace(/'/g,"''")}%' OR TO_CHAR(NVL(PRO.CODGRUPO,0)) = '${String(grupo).replace(/'/g,"''")}')`
      : '';

    const sql = `
SELECT
  PAR.CODPARC,
  PAR.NOMEPARC,
  PRO.CODPROD,
  PRO.DESCRPROD,
  PRO.CODVOL,
  NVL(PRO.CODGRUPOPROD,0) AS CODGRUPO,
  NVL(GRU.DESCRGRUPOPROD,'') AS DESCRGRU,
  NVL(COM.LEADTIME,0) AS LEADTIME,
  NVL(COM.ESTOQUE,0) AS ESTOQUE,
  NVL(COM.EMPENHO,0) AS EMPENHO,
  NVL(COM.COMPRAPEN,0) AS COMPRAPEN,
  NVL(COM.GIROMENSAL,0) AS GIROMENSAL,
  TO_CHAR(COM.DTMELHORPED, 'YYYY-MM-DD"T"HH24:MI:SS') AS DTMELHORPED_ISO
FROM AD_TGFPROCOM COM
JOIN TGFPAR PAR ON PAR.CODPARC = COM.CODPARC
JOIN TGFPRO PRO ON PRO.CODPROD = COM.CODPROD
LEFT JOIN TGFGRU GRU ON GRU.CODGRUPOPROD = PRO.CODGRUPOPROD
WHERE 1=1
  ${filtroFornecedor}
  ${filtroGrupo}
`.trim();

    const rows = await sankhyaQuery(js, sql);

    const items = rows.map(r => {
      const codparc     = Number(r[0]);
      const fornecedor  = String(r[1] ?? '').trim();
      const codprod     = Number(r[2]);
      const descrprod   = String(r[3] ?? '').trim();
      const codvol      = String(r[4] ?? '').trim();
      const codgrupo    = Number(r[5] ?? 0);
      const descrgru    = String(r[6] ?? '').trim();
      const leadtime    = Number(r[7] ?? 0);
      const estoque     = Number(r[8] ?? 0);
      const empenho     = Number(r[9] ?? 0);
      const comprapen   = Number(r[10] ?? 0);
      const giromensal  = Number(r[11] ?? 0);
      const dtmelhorped = r[12] || null;

      const disp     = estoque - empenho + comprapen;
      const consumoD = giromensal > 0 ? (giromensal / 30) : 0;
      const cobertura = consumoD > 0 ? (disp / consumoD) : (disp > 0 ? 9999 : 0);
      const criticoEmDias = leadtime + Number(safetyDays || 0);
      const emRisco = cobertura <= criticoEmDias || disp <= 0;
      const necessidadeSugerida = Math.max(0, Math.ceil((consumoD * criticoEmDias) - disp));

      return {
        codparc, fornecedor,
        codprod, descrprod, codvol,
        codgrupo, descrgru,
        leadtime, estoque, empenho, comprapen, giromensal, dtmelhorped,
        disp, consumoDia: consumoD,
        coberturaDias: Number.isFinite(cobertura) ? Number(cobertura.toFixed(1)) : cobertura,
        risco: emRisco,
        sugestaoCompra: necessidadeSugerida
      };
    });

    const risco = items
      .filter(it => it.risco)
      .sort((a,b) => (a.coberturaDias ?? 99999) - (b.coberturaDias ?? 99999))
      .slice(0, Math.max(5, Math.min(200, Number(top)||30)));

    const byFornecedor = Object.values(
      risco.reduce((acc, it) => {
        const k = it.codparc;
        if (!acc[k]) acc[k] = { codparc: it.codparc, fornecedor: it.fornecedor, itens: 0, sugestaoTotal: 0, dispTotal: 0 };
        acc[k].itens += 1;
        acc[k].sugestaoTotal += it.sugestaoCompra || 0;
        acc[k].dispTotal += it.disp || 0;
        return acc;
      }, {})
    );

    const byGrupo = Object.values(
      risco.reduce((acc, it) => {
        const k = it.codgrupo;
        if (!acc[k]) acc[k] = { codgrupo: it.codgrupo, grupo: it.descrgru, itens: 0, sugestaoTotal: 0, dispTotal: 0 };
        acc[k].itens += 1;
        acc[k].sugestaoTotal += it.sugestaoCompra || 0;
        acc[k].dispTotal += it.disp || 0;
        return acc;
      }, {})
    );

    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const contextJson = JSON.stringify({
      parametros: { safetyDays, top, filtroFornecedor: fornecedor || null, filtroGrupo: grupo || null },
      totais: { itensAvaliados: items.length, itensEmRisco: risco.length },
      rankingRisco: risco,
      porFornecedor: byFornecedor,
      porGrupo: byGrupo
    }, null, 2);

    const system = `
Você é um agente de suprimentos. Responda em PT-BR, direto e acionável.
Use SOMENTE os dados fornecidos no JSON abaixo, sem inventar números.
Explique critério: cobertura <= leadtime + safetyDays OU disponibilidade <= 0.
Dê um sumário por fornecedor e por grupo, e destaque top 10 itens mais críticos com sugestão de compra.
Inclua sempre as fórmulas de cálculo no rodapé (curta).
    `.trim();

    const prompt = `${system}

=== DADOS ===
\`\`\`json
${contextJson}
\`\`\`

=== MENSAGEM DO USUÁRIO ===
"${String(message || '').slice(0, 2000)}"
`;

    const result = await model.generateContent(prompt);
    const reply = result?.response?.text?.() || result?.response?.text || 'Não foi possível gerar a resposta.';

    return res.json({
      reply,
      analysis: {
        safetyDays,
        top: Number(top),
        risco,
        porFornecedor: byFornecedor,
        porGrupo: byGrupo
      }
    });
  } catch (err) {
    console.error('Erro /api/ai/chat:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha no agente de suprimentos' });
  }
});

/* ===================== PROGRAMAÇÃO: KANBAN ===================== */
function mesToIndex(m) {
  if (!m) return null;
  const s = String(m).trim().toLowerCase();
  const map = {
    '01':0,'1':0,'jan':0,'janeiro':0,
    '02':1,'2':1,'fev':1,'fevereiro':1,
    '03':2,'3':2,'mar':2,'março':2,'marco':2,
    '04':3,'4':3,'abr':3,'abril':3,
    '05':4,'5':4,'mai':4,'maio':4,
    '06':5,'6':5,'jun':5,'junho':5,
    '07':6,'7':6,'jul':6,'julho':6,
    '08':7,'8':7,'ago':7,'agosto':7,
    '09':8,'9':8,'set':8,'setembro':8,
    '10':9,'out':9,'outubro':9,
    '11':10,'nov':10,'novembro':10,
    '12':11,'dez':11,'dezembro':11
  };
  return Object.prototype.hasOwnProperty.call(map, s) ? map[s] : null;
}

app.get('/api/producao/kanban', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const anoFiltro = req.query?.ano ? String(req.query.ano).trim() : null;

    const filtros = [`CAB.TIPMOV = 'P'`];
    if (anoFiltro) filtros.push(`(PRJ.AD_ANO = '${anoFiltro}' OR PRJ.AD_ANO IS NULL)`);
    const where = `WHERE ${filtros.join(' AND ')}`;

    const sql = `
SELECT 
  PRJ.CODPROJ,               
  PRJ.IDENTIFICACAO,         
  PAR.CODPARC,               
  PAR.NOMEPARC,              
  CASE 
    WHEN PAI.AD_CODGRUPOPROD IN (020100,020200,020300,020400,021000) THEN 'NX 260-290'
    WHEN PAI.AD_CODGRUPOPROD IN (020800,021400) THEN 'NX 340-350'
    WHEN PAI.AD_CODGRUPOPROD IN (020500,020600) THEN 'NX 360-370'
    WHEN PAI.AD_CODGRUPOPROD IN (020700,021300) THEN 'NX 410'
    WHEN PAI.AD_CODGRUPOPROD IN (021200) THEN 'NX 440'
    WHEN PAI.AD_CODGRUPOPROD IN (020900,021100) THEN 'NX 500'
    ELSE GRU.DESCRGRUPOPROD
  END AS DESCRGRUPOPROD,     
  CASE 
    WHEN PRJ.AD_MES = '01' THEN 'Jan' WHEN PRJ.AD_MES = '02' THEN 'Fev'
    WHEN PRJ.AD_MES = '03' THEN 'Mar' WHEN PRJ.AD_MES = '04' THEN 'Abr'
    WHEN PRJ.AD_MES = '05' THEN 'Mai' WHEN PRJ.AD_MES = '06' THEN 'Jun'
    WHEN PRJ.AD_MES = '07' THEN 'Jul' WHEN PRJ.AD_MES = '08' THEN 'Ago'
    WHEN PRJ.AD_MES = '09' THEN 'Set' WHEN PRJ.AD_MES = '10' THEN 'Out'
    WHEN PRJ.AD_MES = '11' THEN 'Nov' WHEN PRJ.AD_MES = '12' THEN 'Dez'
    ELSE PRJ.AD_MES
  END AS AD_MES,             
  PRJ.AD_ANO,                
  CAB.NUNOTA,                
  PRJ.AD_SEQUENCIAPLAN,      
  PRJ.AD_OBSERVACAO,         
  PRJ.AD_MES||'/'||PRJ.AD_ANO AS MESANO
FROM TCSPRJ PRJ
LEFT JOIN TGFCAB CAB ON PRJ.CODPROJ = CAB.CODPROJ
LEFT JOIN TGFPAR PAR ON PAR.CODPARC = CAB.CODPARC 
JOIN TCSPRJ PAI ON PRJ.CODPROJPAI = PAI.CODPROJ
JOIN TGFGRU GRU ON GRU.CODGRUPOPROD = PAI.AD_CODGRUPOPROD
${where}
`.trim();

    const rows = await sankhyaQuery(js, sql);
    const ops = rows.map(r => {
      const mesIdx = mesToIndex(r[5]);
      const anoNum = r[6] ? Number(r[6]) : null;
      return {
        id: String(r[0]),
        codigo: String(r[1] ?? '').trim(),
        codparc: r[2] != null ? Number(r[2]) : null,
        cliente: String(r[3] ?? '').trim(),
        linhaId: String(r[4] ?? '').trim(),
        mesLabel: r[5] ? String(r[5]) : null,
        ano: Number.isFinite(anoNum) ? anoNum : null,
        mes: Number.isFinite(mesIdx) ? mesIdx : null,
        nunota: r[7] != null ? Number(r[7]) : null,
        sequencia: r[8] != null ? Number(r[8]) : null,
        observacao: String(r[9] ?? '').trim(),
        mesano: String(r[10] ?? '').trim(),
      };
    });

    const linhasSet = new Set(ops.map(o => o.linhaId).filter(Boolean));
    const linhas = Array.from(linhasSet).sort().map(n => ({ id: n, nome: n }));

    res.json({ linhas, ops });
  } catch (err) {
    console.error('GET /api/producao/kanban', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao carregar programação' });
  }
});

// GET /api/producao/financeiro?ident=<IDENTIFICACAO>
app.get('/api/producao/financeiro', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const ident = String(req.query.ident || '').trim();
    if (!ident) return res.status(400).json({ erro: "Parâmetro 'ident' obrigatório" });

    const safe = ident.replace(/'/g, "''");
    const sql = `
      SELECT
        PRJ.IDENTIFICACAO AS CHASSI,
        TIT.DESCRTIPTIT AS TITULO,
        CASE WHEN DET.FAROL =  '<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background-color:#0d4f9b;"></span>'
             THEN DET.VLRPARCELA ELSE 0 END AS VLRPAGO,
        CASE WHEN DET.VLRABERTO > 0 AND DET.DTVENC >= SYSDATE THEN DET.VLRPARCELA ELSE 0 END  AS VLRAVENCER,
        CASE WHEN DET.VLRABERTO > 0 AND DET.DTVENC < SYSDATE THEN DET.VLRPARCELA ELSE 0 END  AS VLRAVENCIDO,
        CASE WHEN TO_CHAR(DET.DTVENC,'DD/MM/YYYY') > TO_CHAR(SYSDATE ,'DD/MM/YYYY') THEN 0 ELSE DET.DIASATRASO END AS DIASATRASOS,
        TO_CHAR(DET.DTVENC,'DD/MM/YYYY') AS DTVENC,
        DET.NUFIN,
        DET.NUNOTA,
        DET.VLRPARCELA,
        CASE
          WHEN DET.FAROL = '<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background-color:#9b0d0d;"></span>' THEN 'ATRASADO'
          WHEN DET.FAROL = '<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background-color:#0d9b14;"></span>' THEN 'EM ABERTO'
          WHEN DET.FAROL = '<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background-color:#0d4f9b;"></span>' THEN 'PAGO'
          ELSE '—'
        END AS STATUS
      FROM AD_FINGERCODET DET
      JOIN TGFCAB CAB ON CAB.NUNOTA = DET.NUNOTA
      JOIN TGFPAR PAR ON PAR.CODPARC = CAB.CODPARC
      JOIN TCSPRJ PRJ ON PRJ.CODPROJ = CAB.CODPROJ
      JOIN TGFTIT TIT ON TIT.CODTIPTIT = DET.CODTIPTIT
      WHERE PRJ.IDENTIFICACAO = '${safe}'
    `.trim();

    const rows = await sankhyaQuery(js, sql);

    const items = rows.map(r => ({
      chassi: String(r[0] ?? ''),
      titulo: String(r[1] ?? ''),
      vlrPago: Number(r[2] ?? 0),
      vlrAVencer: Number(r[3] ?? 0),
      vlrAVencido: Number(r[4] ?? 0),
      diasAtraso: Number(r[5] ?? 0),
      dtVenc: String(r[6] ?? ''),
      nufin: Number(r[7] ?? 0),
      nunota: Number(r[8] ?? 0),
      vlrParcela: Number(r[9] ?? 0),
      status: String(r[10] ?? '—'),
    }));

    res.json({ items });
  } catch (err) {
    console.error('GET /api/producao/financeiro', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao consultar financeiro' });
  }
});

// GET /api/producao/pedido?ident=<IDENTIFICACAO>
app.get('/api/producao/pedido', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const ident = String(req.query.ident || '').trim();
    if (!ident) return res.status(400).json({ erro: "Parâmetro 'ident' obrigatório" });

    const safe = ident.replace(/'/g, "''");
    const sql = `
      SELECT
          CAB.NUNOTA ,
          CAB.CODPARC ,
          PAR.NOMEPARC , 
          CAB.OBSERVACAO , 
          AD_EXPORTACAO , 
          CAB.AD_CORDOEVA ,
          CAB.AD_CORDOBARCO , 
          CAB.AD_CORESTOFADO,
          VEN.APELIDO
      FROM TGFCAB CAB 
      JOIN TGFPAR PAR ON PAR.CODPARC = CAB.CODPARC 
      JOIN TGFVEN VEN ON VEN.CODVEND = CAB.CODVEND
      JOIN TCSPRJ PRJ ON PRJ.CODPROJ = CAB.CODPROJ
      WHERE PRJ.IDENTIFICACAO = '${safe}'
        AND CAB.TIPMOV = 'P'
    `.trim();

    const rows = await sankhyaQuery(js, sql);

    const items = rows.map(r => ({
      nunota: String(r[0] ?? ''),
      codparc: String(r[1] ?? ''),
      nomeparc: String(r[2] ?? ''),
      observacao: String(r[3] ?? ''),
      ad_exportacao: String(r[4] ?? ''),
      ad_cordoeva: String(r[5] ?? ''),
      ad_cordobarco: String(r[6] ?? ''),
      corestofado: String(r[7] ?? ''),
      apelido: String(r[8] ?? ''),
    }));

    res.json({ items });
  } catch (err) {
    console.error('GET /api/producao/pedido', err?.response?.data || err.message);
    res.status(500).json({ erro: 'Falha ao consultar financeiro/pedido' });
  }
});

/* ===================== FINANCEIRO: FLUXO / CATEGORIAS / DRE ===================== */
// FLUXO DE CAIXA DIÁRIO
app.get('/api/financeiro/fluxo', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const iniBR = toBRDate(req.query.ini);
    const fimBR = toBRDate(req.query.fim);
    const saldoInicial =
      (req.query.saldoInicial != null ? Number(req.query.saldoInicial) : null)
      ?? (process.env.SALDO_INICIAL ? Number(process.env.SALDO_INICIAL) : 0);

    if (!iniBR || !fimBR) {
      return res.status(400).json({ erro: "Parâmetros inválidos. Use dd/mm/aaaa ou aaaa-mm-dd." });
    }

    const sql = `
WITH BASE AS (
  SELECT DTVENC, SUM(VLRLIQ) AS VLRLIQ, SUM(VLRDESP) AS VLRDESP
  FROM (
    SELECT DTVENC, T AS VLRLIQ, 0 AS VLRDESP
      FROM V_TF_FINANCEIRO_ABERTO
    UNION ALL
    SELECT DTVENC, 0 AS VLRLIQ, VLRDESDOB
      FROM TGFFIN
     WHERE RECDESP = -1
       AND CODTIPTIT <> 30
       AND DHBAIXA IS NULL
       AND CODTIPTIT <> 30
  )
  WHERE DTVENC BETWEEN TO_DATE('${iniBR}','DD/MM/YYYY') AND TO_DATE('${fimBR}','DD/MM/YYYY')
  GROUP BY DTVENC
)
SELECT
  TO_CHAR(DTVENC, 'YYYY-MM-DD') AS DTVENC_ISO,
  RTRIM(TO_CHAR(DTVENC, 'Day', 'NLS_DATE_LANGUAGE=Portuguese')) AS DIA_SEMANA,
  VLRLIQ,
  VLRDESP,
  ${Number.isFinite(saldoInicial) ? saldoInicial : 0} +
    SUM(VLRLIQ - VLRDESP) OVER (ORDER BY DTVENC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
    AS SALDO
FROM BASE
ORDER BY DTVENC
`.trim();

    const rows = await sankhyaQuery(js, sql);

    const items = (rows || []).map(r => ({
      dataISO: String(r[0]),
      diaSemana: String(r[1] || "").trim(),
      receita: Number(r[2] || 0),
      despesa: Number(r[3] || 0),
      saldo: Number(r[4] || 0),
    }));

    return res.json({ items });
  } catch (err) {
    console.error('Erro /api/financeiro/fluxo:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao consultar fluxo de caixa' });
  }
});

// CATEGORIAS (resumo)
app.get('/api/financeiro/categorias', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const iniBR = toBRDate(req.query.ini);
    const fimBR = toBRDate(req.query.fim);
    const base  = String(req.query.base || 'venc').toLowerCase(); // 'venc' | 'baixa'
    const codemp = req.query.codemp ? Number(req.query.codemp) : null;

    if (!iniBR || !fimBR) {
      return res.status(400).json({ erro: "Parâmetros inválidos. Use dd/mm/aaaa ou aaaa-mm-dd." });
    }

    const dateField = base === 'baixa' ? 'FIN.DHBAIXA' : 'FIN.DTVENC';
    const empFilter = codemp ? `AND FIN.CODEMP = ${codemp}` : '';
    const tpbaixaFilter = `(FIN.CODTIPOPERBAIXA IS NULL OR FIN.CODTIPOPERBAIXA NOT IN (1709,1708))`;

    const sql = `
SELECT 
  NAT.DESCRNAT AS DESCRNAT,
  SUM(CASE WHEN FIN.RECDESP =  1 THEN ABS(FIN.VLRDESDOB) ELSE 0 END) AS RECEITA,
  SUM(CASE WHEN FIN.RECDESP = -1 THEN ABS(FIN.VLRDESDOB) ELSE 0 END) AS DESPESA,
  ( SUM(CASE WHEN FIN.RECDESP = 1 THEN ABS(FIN.VLRDESDOB) ELSE 0 END)
  - SUM(CASE WHEN FIN.RECDESP = -1 THEN ABS(FIN.VLRDESDOB) ELSE 0 END) ) AS RESULTADO,
  NAT.CODNAT
FROM TGFFIN FIN
JOIN TGFNAT NAT ON NAT.CODNAT = FIN.CODNAT
WHERE ${dateField} BETWEEN TO_DATE('${iniBR}','DD/MM/YYYY') AND TO_DATE('${fimBR}','DD/MM/YYYY')
  AND ${tpbaixaFilter}
  ${empFilter}
GROUP BY NAT.DESCRNAT, NAT.CODNAT
ORDER BY RESULTADO DESC
`.trim();

    const rows = await sankhyaQuery(js, sql);
    const items = (rows || []).map(r => ({
      categoria: String(r[0] ?? ''),
      receita: Number(r[1] ?? 0),
      despesa: Number(r[2] ?? 0),
      resultado: Number(r[3] ?? 0),
      codnat: Number(r[4] ?? 0),
    }));
    return res.json({ items, meta: { base } });
  } catch (err) {
    console.error('Erro /api/financeiro/categorias:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao consultar categorias' });
  }
});

// Títulos por categoria
app.get('/api/financeiro/categorias/:codnat/titulos', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const codnat = Number(req.params.codnat);
    const iniBR  = toBRDate(req.query.ini);
    const fimBR  = toBRDate(req.query.fim);
    const base   = String(req.query.base || 'venc').toLowerCase();
    const codemp = req.query.codemp ? Number(req.query.codemp) : null;

    if (!codnat || !iniBR || !fimBR) {
      return res.status(400).json({ erro: "Parâmetros inválidos (codnat, ini, fim)." });
    }

    const dateField = base === 'baixa' ? 'FIN.DHBAIXA' : 'FIN.DTVENC';
    const empFilter = codemp ? `AND FIN.CODEMP = ${codemp}` : '';
    const tpbaixaFilter = `(FIN.CODTIPOPERBAIXA IS NULL OR FIN.CODTIPOPERBAIXA NOT IN (1709,1708))`;

    const sql = `
SELECT
  FIN.NUFIN,
  PAR.NOMEPARC,
  NAT.DESCRNAT,
  CASE WHEN FIN.RECDESP=1 THEN 'RECEBER' ELSE 'PAGAR' END AS TIPO,
  TO_CHAR(${dateField}, 'YYYY-MM-DD"T"HH24:MI:SS') AS DATA_REF,
  ABS(FIN.VLRDESDOB) AS VALOR,
  TIT.DESCRTIPTIT
FROM TGFFIN FIN
JOIN TGFPAR PAR ON PAR.CODPARC = FIN.CODPARC
JOIN TGFNAT NAT ON NAT.CODNAT = FIN.CODNAT
LEFT JOIN TGFTIT TIT ON TIT.CODTIPTIT = FIN.CODTIPTIT
WHERE FIN.CODNAT = ${codnat}
  AND ${dateField} BETWEEN TO_DATE('${iniBR}','DD/MM/YYYY') AND TO_DATE('${fimBR}','DD/MM/YYYY')
  AND ${tpbaixaFilter}
  ${empFilter}
ORDER BY ${dateField} DESC, FIN.NUFIN DESC
`.trim();

    const rows = await sankhyaQuery(js, sql);
    const items = (rows || []).map(r => ({
      nufin: Number(r[0] ?? 0),
      parceiro: String(r[1] ?? ''),
      categoria: String(r[2] ?? ''),
      tipo: String(r[3] ?? ''),
      dataRefISO: String(r[4] ?? null),
      valor: Number(r[5] ?? 0),
      tipoTitulo: String(r[6] ?? ''),
    }));
    return res.json({ items, meta: { base } });
  } catch (err) {
    console.error('Erro /api/financeiro/categorias/:codnat/titulos:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao consultar títulos da categoria' });
  }
});

// DRE por barco
app.get('/api/financeiro/dre-barcos', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const iniBR = toBRDate(req.query.ini);
    const fimBR = toBRDate(req.query.fim);
    if (!iniBR || !fimBR) {
      return res.status(400).json({ erro: "Parâmetros inválidos. Use dd/mm/aaaa ou aaaa-mm-dd." });
    }

    const sql = `
SELECT
  CAB.NUNOTA,
  PROC.IDIPROC,
  IP.NROLOTE,
  PRJ.IDENTIFICACAO AS CHASSI,
  CAB.VLRNOTA AS FATURAMENTO,
  C.VLRTOT AS CUSTO,
  0 AS CUSTO_MAO_OBRA,
  0 AS CUSTO_ADM,
  (CAB.VLRNOTA - C.VLRTOT) AS LUCRO
FROM TGFCAB CAB
JOIN TPRIPROC PROC ON PROC.AD_CODPROJ = CAB.CODPROJ
JOIN (
  SELECT C.IDIPROC, SUM(I.VLRTOT) AS VLRTOT
    FROM TGFCAB C
    JOIN TGFITE I ON I.NUNOTA = C.NUNOTA AND I.SEQUENCIA > 1
   WHERE C.TIPMOV = 'F'
   GROUP BY C.IDIPROC
) C ON C.IDIPROC = PROC.IDIPROC
JOIN TPRIPA IP ON PROC.IDIPROC = IP.IDIPROC
JOIN TCSPRJ PRJ ON PRJ.CODPROJ = CAB.CODPROJ
WHERE CAB.TIPMOV = 'P'
  AND PROC.DHTERMINO BETWEEN TO_DATE('${iniBR}','DD/MM/YYYY') AND TO_DATE('${fimBR}','DD/MM/YYYY')
ORDER BY PRJ.IDENTIFICACAO
`.trim();

    const rows = await sankhyaQuery(js, sql);

    const items = (rows || []).map(r => ({
      nunota: Number(r[0] ?? 0),
      idiproc: Number(r[1] ?? 0),
      nroLote: String(r[2] ?? '').trim(),
      chassi: String(r[3] ?? '').trim(),
      receita: Number(r[4] ?? 0),
      custoDireto: Number(r[5] ?? 0),
      maoObra: Number(r[6] ?? 0),
      adm: Number(r[7] ?? 0),
      lucro: Number(r[8] ?? 0),
    }));

    return res.json({ items });
  } catch (err) {
    console.error('Erro /api/financeiro/dre-barcos:', err?.response?.data || err.message);
    return res.status(500).json({ erro: 'Falha ao consultar DRE por barco' });
  }
});

/* ===================== DATASET SAVE (DatasetSP.save) ===================== */
app.post("/api/sankhya/dataset/save", auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user;
    const js = await sankhyaLogin(usuario, senha);

    const { entity, fields, pk, fk, values, crudListener } = req.body || {};
    if (!entity || !Array.isArray(fields) || !values) {
      return res.status(400).json({
        erro: "Parâmetros inválidos: 'entity', 'fields[]' e 'values' são obrigatórios.",
      });
    }

    const out = await sankhyaDatasetSave(js, { entity, fields, pk, fk, values, crudListener });
    res.json(out);
  } catch (err) {
    console.error("POST /api/sankhya/dataset/save:", err?.response?.data || err.message);
    res.status(500).json({ erro: "Falha no DatasetSP.save", detalhe: err?.message || undefined });
  }
});

// ===== helper: CACSP.incluirNota =====
async function sankhyaIncluirNota(jsessionid, { cabecalho, items, informarPreco = false }) {
  if (!cabecalho || !Array.isArray(items) || items.length === 0) {
    throw new Error("Parâmetros inválidos: 'cabecalho' e 'items[]' são obrigatórios.");
  }

  // Monta o payload idêntico ao do Flutter
  const payload = {
    requestBody: {
      nota: {
        cabecalho,
        itens: {
          INFORMARPRECO: informarPreco ? "True" : "False",
          item: items,
        },
      },
    },
  };

  // Chamada ao serviço CACSP.incluirNota
  const url = `${SANKHYA_URL}/mgecom/service.sbr?mgeSession=${jsessionid}&serviceName=CACSP.incluirNota&outputType=json`;

  const r = await sankhya.post(url, payload, {
    headers: { Cookie: `JSESSIONID=${jsessionid}` },
  });

  if (r.status >= 400) throw new Error(`HTTP ${r.status}`);

  // Normaliza saída no mesmo formato que você usa no Flutter
  return {
    STATUS: r.data?.status,         // "1" = ok, "0" = erro na maioria dos casos
    REQUISICAO: payload,            // o que foi enviado
    RETORNO: r.data,                // resposta bruta do Sankhya
  };
}

// ===== rota: POST /api/pedidos/incluir =====
// body: { cabecalho: {...}, items: [{...}, ...], informarPreco?: boolean }
app.post('/api/pedidos/incluir', auth, async (req, res) => {
  try {
    const { usuario, senha } = req.user || {};
    if (!usuario || !senha) {
      return res.status(401).json({ erro: 'Sessão inválida (usuário sem credenciais no token).' });
    }

    // reloga a cada requisição
    const js = await sankhyaLogin(usuario, senha);

    const { cabecalho, items, informarPreco = false } = req.body || {};

    // validação simples
    if (!cabecalho || !Array.isArray(items) || !items.length) {
      return res.status(400).json({ erro: "Informe 'cabecalho' e 'items[]'." });
    }

    const out = await sankhyaIncluirNota(js, { cabecalho, items, informarPreco });

    // Mantém o contrato do Flutter
    return res.json(out);
  } catch (err) {
    console.error('POST /api/pedidos/incluir:', err?.response?.data || err.message);
    // Tenta devolver algo parecido com o contrato Flutter em caso de erro
    return res.status(500).json({
      STATUS: '0',
      REQUISICAO: {
        requestBody: {
          nota: {
            cabecalho: req.body?.cabecalho || null,
            itens: { INFORMARPRECO: (req.body?.informarPreco ? "True" : "False"), item: req.body?.items || [] },
          },
        },
      },
      RETORNO: { erro: 'Falha ao incluir pedido', detalhe: err?.message || 'Erro desconhecido' },
    });
  }
});


/* ===================== WHOAMI ===================== */
app.get('/api/whoami', auth, (req, res) => {
  const { usuario, codvend, name } = req.user || {};
  res.json({ user: { usuario, codvend, name }, hasSankhya: true });
});

/* ===================== START ===================== */
app.listen(PORT, () => console.log(`API em http://localhost:${PORT}`));
