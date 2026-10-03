// Intermediário seguro LB — integração com TikTok Shop API (GMV + Cupons/Ofertas)
// Variáveis de ambiente necessárias na Vercel:
//   TIKTOK_APP_KEY, TIKTOK_APP_SECRET, TIKTOK_REDIRECT_URI
import crypto from 'crypto';

const BASE_URL = 'https://open-api.tiktokglobalshop.com';
const AUTH_URL = 'https://auth.tiktok-shops.com';

// Assina a requisição no formato exato exigido pela TikTok Shop:
// HMAC-SHA256(appSecret + path + params_ordenados_concatenados + appSecret, chave=appSecret)
function assinarRequisicao(path, params, appSecret) {
  // access_token ENTRA na assinatura (confirmado com um exemplo real que funcionou) — só "sign" fica de fora
  const chavesOrdenadas = Object.keys(params).filter(k => k !== 'sign' && k !== '__debug_sign').sort();
  let base = appSecret + path;
  for (const chave of chavesOrdenadas) {
    base += chave + params[chave];
  }
  base += appSecret;
  return crypto.createHmac('sha256', appSecret).update(base).digest('hex');
}

async function chamarTiktok(path, params = {}, metodo = 'GET', body = null, accessToken = null) {
  // .trim() por segurança — espaço/quebra de linha escondido ao colar na Vercel já causou
  // "sign inválido" antes, mesmo com a fórmula certa.
  const appKey = (process.env.TIKTOK_APP_KEY || '').trim();
  const appSecret = (process.env.TIKTOK_APP_SECRET || '').trim();
  const timestamp = Math.floor(Date.now() / 1000);

  // A TikTok exige "version" como parâmetro comum em toda chamada (faltava aqui — causava "invalid sign")
  const todosParams = { app_key: appKey, timestamp: String(timestamp), version: '202309', ...params };
  if (accessToken) todosParams.access_token = accessToken; // também entra na URL, além do header
  const sign = assinarRequisicao(path, todosParams, appSecret);

  // __debug_sign nunca pode ir na requisição de verdade pra TikTok — é só pra pedir o relatório
  // de volta pro nosso backend. Antes vazava aqui, o que por si só já invalidava a assinatura.
  const { __debug_sign, ...paramsParaEnviar } = todosParams;
  const query = new URLSearchParams({ ...paramsParaEnviar, sign }).toString();
  const url = `${BASE_URL}${path}?${query}`;

  const headers = { 'Content-Type': 'application/json' };
  if (accessToken) headers['x-tts-access-token'] = accessToken;

  console.log('[TikTok] URL final:', url);
  console.log('[TikTok] Sign:', sign);
  console.log('[TikTok] Base assinada:', `${path}${Object.keys(todosParams).filter(k=>k!=='sign'&&k!=='__debug_sign').sort().map(k=>k+todosParams[k]).join('')}`);

  const resp = await fetch(url, {
    method: metodo,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const resultado = await resp.json();
  resultado.http_status = resp.status; // a tela de diagnóstico mostra isso — a TikTok não manda no corpo

  if (params.__debug_sign) {
    const chavesOrdenadas = Object.keys(todosParams).filter(k => k !== 'sign' && k !== '__debug_sign').sort();
    resultado.__debug = { url, sign, base_sem_segredo: `[SEGREDO]${path}${chavesOrdenadas.map(k => k + todosParams[k]).join('')}[SEGREDO]` };
  }
  return resultado;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const appKey = (process.env.TIKTOK_APP_KEY || '').trim();
  const appSecret = (process.env.TIKTOK_APP_SECRET || '').trim();
  const redirectUri = (process.env.TIKTOK_REDIRECT_URI || '').trim();
  if (!appKey || !appSecret) return res.status(500).json({ erro: 'Credenciais do TikTok Shop não configuradas na Vercel.' });

  try {
    const params = req.method === 'GET' ? req.query : req.body;
    const { acao } = params;

    // Gera o link de autorização pra o lojista conectar a loja dele (identifica o cliente via "state")
    if (acao === 'diagnostico') {
      return res.status(200).json({
        ok: true,
        appKey_tamanho: appKey.length,
        appKey_valor: appKey,
        appSecret_tamanho: appSecret.length,
        appSecret_primeiros3: appSecret.slice(0, 3),
        appSecret_ultimos3: appSecret.slice(-3),
        horario_servidor: new Date().toISOString(),
        timestamp_unix: Math.floor(Date.now() / 1000)
      });
    }

    if (acao === 'gerar_link_autorizacao') {
      const { clienteId } = params;
      if (!clienteId) return res.status(400).json({ erro: 'clienteId é obrigatório.' });
      const url = `${AUTH_URL}/oauth/authorize?app_key=${appKey}&state=${encodeURIComponent(clienteId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
      return res.status(200).json({ ok: true, url });
    }

    // Troca o "code" (recebido no redirecionamento) por um access_token de verdade,
    // e já busca a(s) loja(s) autorizada(s) com esse token (id + cipher — a TikTok exige
    // os dois em quase toda chamada, não só o shop_id).
    if (acao === 'trocar_codigo') {
      const { code } = params;
      if (!code) return res.status(400).json({ erro: 'code é obrigatório.' });
      const resp = await fetch(`${AUTH_URL}/api/v2/token/get?app_key=${appKey}&app_secret=${appSecret}&auth_code=${code}&grant_type=authorized_code`);
      const data = await resp.json();
      if (data.code !== 0) {
        // Falhou ANTES de ter token nenhum — a tela de diagnóstico espera esses nomes de campo exatos.
        return res.status(200).json({
          ok: false, etapa: 'trocar_codigo', token_obtido: false,
          erro: data.message || 'Falha ao trocar o código.',
          resposta_tiktok_lojas: { code: data.code, message: data.message, http_status: resp.status, request_id: data.request_id }
        });
      }

      const accessToken = data.data.access_token;
      const grantedScopes = data.data.scope || data.data.granted_scopes || null; // nome do campo varia conforme a doc/versão
      const userId = data.data.open_id || data.data.user_id || null;
      const expiraEm = data.data.access_token_expire_in || null;

      // __debug_sign sempre ligado aqui (não vaza o segredo — só a base sem ele) — assim, se essa
      // chamada falhar, a resposta já vem com o motivo exato, sem precisar de um 2º teste manual.
      const lojas = await chamarTiktok('/authorization/202309/shops', { __debug_sign: '1' }, 'GET', null, accessToken);
      const listaLojas = lojas?.data?.shops || [];
      if (!listaLojas.length) {
        return res.status(200).json({
          ok: false, etapa: 'buscar_lojas', token_obtido: true,
          erro: lojas?.message || 'Token obtido, mas nenhuma loja autorizada foi encontrada.',
          resposta_tiktok_lojas: lojas,
          granted_scopes: grantedScopes, user_id: userId, token_expira_em: expiraEm
        });
      }
      const loja = listaLojas[0]; // LB conecta 1 loja por cliente — pega a primeira

      return res.status(200).json({
        ok: true,
        access_token: accessToken,
        refresh_token: data.data.refresh_token,
        expires_in: expiraEm,
        shop_id: loja.id,
        shop_cipher: loja.cipher,
        shop_name: loja.name
      });
    }

    // Busca o GMV (soma dos pedidos) num período, pra um shop_id + shop_cipher + access_token específicos
    if (acao === 'buscar_gmv') {
      const { access_token, shop_id, shop_cipher, data_inicio, data_fim, __debug_sign } = params;
      if (!access_token || !shop_id || !shop_cipher) return res.status(400).json({ erro: 'access_token, shop_id e shop_cipher são obrigatórios.' });

      const path = '/order/202309/orders/search';
      const timeFromTotal = Math.floor(new Date(data_inicio).getTime() / 1000);
      const timeToTotal = Math.floor(new Date(data_fim).getTime() / 1000);

      let gmvTotal = 0, totalPedidos = 0, pageToken = '';
      let seguir = true;
      while (seguir) {
        // page_size e page_token vão na URL (parâmetros comuns) — só os filtros de data vão no corpo
        const queryParams = { shop_id, shop_cipher, page_size: '50', ...(pageToken ? { page_token: pageToken } : {}), ...(__debug_sign ? { __debug_sign: '1' } : {}) };
        const bodyBusca = { create_time_ge: timeFromTotal, create_time_lt: timeToTotal };
        const resultado = await chamarTiktok(path, queryParams, 'POST', bodyBusca, access_token);
        if (__debug_sign) return res.status(200).json(resultado);
        if (resultado.code !== 0) return res.status(200).json({ ok: false, erro: resultado.message || 'Erro ao buscar pedidos.' });

        const pedidos = resultado.data?.orders || [];
        pedidos.forEach(p => { gmvTotal += Number(p.payment?.total_amount || 0); totalPedidos++; });

        pageToken = resultado.data?.next_page_token || '';
        seguir = !!pageToken;
      }
      return res.status(200).json({ ok: true, gmv: gmvTotal, total_pedidos: totalPedidos });
    }

    // Cria uma promoção (desconto por produto OU oferta relâmpago — mesmo endpoint da TikTok,
    // diferenciado pelo campo activity_type). ATENÇÃO: os campos abaixo (title, activity_type,
    // product_level, begin_time, end_time) são confirmados pela própria ferramenta de teste da
    // TikTok. A estrutura da lista de produtos (products/discount) NÃO foi confirmada ainda —
    // teste esse corpo na "Ferramenta de teste de API" (Editar JSON) antes de confiar no cron.
    if (acao === 'criar_promocao') {
      const { access_token, shop_id, shop_cipher, tipo, percentual, produtos, duracao_dias } = params;
      if (!access_token || !shop_id || !shop_cipher) return res.status(400).json({ erro: 'access_token, shop_id e shop_cipher são obrigatórios.' });
      if (!produtos || !produtos.length) return res.status(400).json({ erro: 'produtos (lista de product_id) é obrigatório.' });

      const agora = Math.floor(Date.now() / 1000);
      const dias = tipo === 'FLASH_SALE' ? Math.min(duracao_dias || 3, 3) : (duracao_dias || 90); // Flash Deal: máx 3 dias
      const fim = agora + dias * 24 * 60 * 60;

      const corpo = {
        title: `${tipo === 'FLASH_SALE' ? 'Oferta Relâmpago' : 'Desconto'} - LB Marketplace`,
        activity_type: tipo, // 'DISCOUNT' ou 'FLASH_SALE' — NÃO CONFIRMADO, testar antes
        product_level: 'PRODUCT', // NÃO CONFIRMADO
        begin_time: agora,
        end_time: fim,
        products: produtos.map(p => ({
          product_id: p.product_id,
          discount: { type: 'PERCENTAGE_OFF', percentage: percentual || 5 } // ESTRUTURA NÃO CONFIRMADA
        }))
      };

      const resultado = await chamarTiktok('/promotion/202309/activities', { shop_id, shop_cipher }, 'POST', corpo, access_token);
      if (resultado.code !== 0) {
        return res.status(200).json({ ok: false, erro: resultado.message || 'Erro ao criar promoção.', debug: resultado, corpoEnviado: corpo });
      }
      return res.status(200).json({ ok: true, activity_id: resultado.data?.activity_id, inicio: agora, fim, debug: resultado });
    }

    return res.status(400).json({ erro: 'Ação não reconhecida.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ erro: 'Erro interno: ' + (e.message || 'desconhecido') });
  }
}
