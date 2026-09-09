// Intermediário seguro LB — integração com TikTok Shop API (GMV + Cupons/Ofertas)
// Variáveis de ambiente necessárias na Vercel:
//   TIKTOK_APP_KEY, TIKTOK_APP_SECRET, TIKTOK_REDIRECT_URI
import crypto from 'crypto';

const BASE_URL = 'https://open-api.tiktokglobalshop.com';
const AUTH_URL = 'https://auth.tiktok-shops.com';

// Assina a requisição no formato exato exigido pela TikTok Shop:
// HMAC-SHA256(appSecret + path + params_ordenados_concatenados + appSecret, chave=appSecret)
function assinarRequisicao(path, params, appSecret) {
  const chavesOrdenadas = Object.keys(params).filter(k => k !== 'sign' && k !== 'access_token').sort();
  let base = appSecret + path;
  for (const chave of chavesOrdenadas) {
    base += chave + params[chave];
  }
  base += appSecret;
  return crypto.createHmac('sha256', appSecret).update(base).digest('hex');
}

async function chamarTiktok(path, params = {}, metodo = 'GET', body = null, accessToken = null) {
  const appKey = process.env.TIKTOK_APP_KEY;
  const appSecret = process.env.TIKTOK_APP_SECRET;
  const timestamp = Math.floor(Date.now() / 1000);

  const todosParams = { app_key: appKey, timestamp: String(timestamp), ...params };
  const sign = assinarRequisicao(path, todosParams, appSecret);

  const query = new URLSearchParams({ ...todosParams, sign }).toString();
  const url = `${BASE_URL}${path}?${query}`;

  const headers = { 'Content-Type': 'application/json' };
  if (accessToken) headers['x-tts-access-token'] = accessToken;

  const resp = await fetch(url, {
    method: metodo,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  return resp.json();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const appKey = process.env.TIKTOK_APP_KEY;
  const appSecret = process.env.TIKTOK_APP_SECRET;
  const redirectUri = process.env.TIKTOK_REDIRECT_URI;
  if (!appKey || !appSecret) return res.status(500).json({ erro: 'Credenciais do TikTok Shop não configuradas na Vercel.' });

  try {
    const params = req.method === 'GET' ? req.query : req.body;
    const { acao } = params;

    // Gera o link de autorização pra o lojista conectar a loja dele (identifica o cliente via "state")
    if (acao === 'gerar_link_autorizacao') {
      const { clienteId } = params;
      if (!clienteId) return res.status(400).json({ erro: 'clienteId é obrigatório.' });
      const url = `${AUTH_URL}/oauth/authorize?app_key=${appKey}&state=${encodeURIComponent(clienteId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
      return res.status(200).json({ ok: true, url });
    }

    // Troca o "code" (recebido no redirecionamento) por um access_token de verdade
    if (acao === 'trocar_codigo') {
      const { code } = params;
      if (!code) return res.status(400).json({ erro: 'code é obrigatório.' });
      const resp = await fetch(`${AUTH_URL}/api/v2/token/get?app_key=${appKey}&app_secret=${appSecret}&auth_code=${code}&grant_type=authorized_code`);
      const data = await resp.json();
      if (data.code !== 0) return res.status(200).json({ ok: false, erro: data.message || 'Falha ao trocar o código.' });
      return res.status(200).json({ ok: true, access_token: data.data.access_token, refresh_token: data.data.refresh_token, shop_id: data.data.seller_name, expires_in: data.data.access_token_expire_in });
    }

    // Busca o GMV (soma dos pedidos) num período, pra um shop_id + access_token específicos
    if (acao === 'buscar_gmv') {
      const { access_token, data_inicio, data_fim } = params;
      if (!access_token) return res.status(400).json({ erro: 'access_token é obrigatório.' });

      const path = '/order/202309/orders/search';
      const timeFromTotal = Math.floor(new Date(data_inicio).getTime() / 1000);
      const timeToTotal = Math.floor(new Date(data_fim).getTime() / 1000);

      let gmvTotal = 0, totalPedidos = 0, pageToken = '';
      let seguir = true;
      while (seguir) {
        const bodyBusca = {
          create_time_ge: timeFromTotal,
          create_time_lt: timeToTotal,
          page_size: 50,
          ...(pageToken ? { page_token: pageToken } : {})
        };
        const resultado = await chamarTiktok(path, {}, 'POST', bodyBusca, access_token);
        if (resultado.code !== 0) return res.status(200).json({ ok: false, erro: resultado.message || 'Erro ao buscar pedidos.' });

        const pedidos = resultado.data?.orders || [];
        pedidos.forEach(p => { gmvTotal += Number(p.payment?.total_amount || 0); totalPedidos++; });

        pageToken = resultado.data?.next_page_token || '';
        seguir = !!pageToken;
      }
      return res.status(200).json({ ok: true, gmv: gmvTotal, total_pedidos: totalPedidos });
    }

    return res.status(400).json({ erro: 'Ação não reconhecida.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ erro: 'Erro interno: ' + (e.message || 'desconhecido') });
  }
}
