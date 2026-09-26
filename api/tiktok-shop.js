// Intermediário seguro LB — integração com TikTok Shop API (GMV + Cupons/Ofertas)
// Variáveis de ambiente necessárias na Vercel:
//   TIKTOK_APP_KEY, TIKTOK_APP_SECRET, TIKTOK_REDIRECT_URI
import crypto from 'crypto';

const BASE_URL = 'https://open-api.tiktokglobalshop.com';
const AUTH_URL = 'https://auth.tiktok-shops.com';

// Assina a requisição no formato exato exigido pela TikTok Shop:
function assinarRequisicao(path, params, appSecret) {
  const chavesOrdenadas = Object.keys(params)
    .filter(k => k !== 'sign' && k !== '__debug_sign')
    .sort();

  let base = appSecret + path;

  for (const chave of chavesOrdenadas) {
    base += chave + params[chave];
  }

  base += appSecret;

  return crypto
    .createHmac('sha256', appSecret)
    .update(base)
    .digest('hex');
}

async function chamarTiktok(
  path,
  params = {},
  metodo = 'GET',
  body = null,
  accessToken = null
) {
  const appKey = (process.env.TIKTOK_APP_KEY || '').trim();
  const appSecret = (process.env.TIKTOK_APP_SECRET || '').trim();
  const timestamp = Math.floor(Date.now() / 1000);

  const todosParams = {
    app_key: appKey,
    timestamp: String(timestamp),
    version: '202309',
    ...params
  };

  if (accessToken) {
    todosParams.access_token = accessToken;
  }

  const sign = assinarRequisicao(
    path,
    todosParams,
    appSecret
  );

  const query = new URLSearchParams({
    ...todosParams,
    sign
  }).toString();

  const url = `${BASE_URL}${path}?${query}`;

  const headers = {
    'Content-Type': 'application/json'
  };

  if (accessToken) {
    headers['x-tts-access-token'] = accessToken;
  }

  console.log('[TikTok] URL final:', url);
  console.log('[TikTok] Sign:', sign);

  const resp = await fetch(url, {
    method: metodo,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const resultado = await resp.json();

  if (params.__debug_sign) {
    const chavesOrdenadas = Object.keys(todosParams)
      .filter(
        k => k !== 'sign' && k !== '__debug_sign'
      )
      .sort();

    resultado.__debug = {
      url,
      sign,
      base_sem_segredo:
        `[SEGREDO]${path}` +
        `${chavesOrdenadas
          .map(k => k + todosParams[k])
          .join('')}` +
        `[SEGREDO]`
    };
  }

  return resultado;
}

export default async function handler(req, res) {
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate'
  );

  res.setHeader(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const appKey =
    (process.env.TIKTOK_APP_KEY || '').trim();

  const appSecret =
    (process.env.TIKTOK_APP_SECRET || '').trim();

  const redirectUri =
    (process.env.TIKTOK_REDIRECT_URI || '').trim();

  if (!appKey || !appSecret) {
    return res.status(500).json({
      erro:
        'Credenciais do TikTok Shop não configuradas na Vercel.'
    });
  }

  try {
    const params =
      req.method === 'GET'
        ? req.query
        : req.body;

    const { acao } = params;

    // Diagnóstico
    if (acao === 'diagnostico') {
      return res.status(200).json({
        ok: true,
        appKey_tamanho: appKey.length,
        appKey_valor: appKey,
        appSecret_tamanho: appSecret.length,
        appSecret_primeiros3:
          appSecret.slice(0, 3),
        appSecret_ultimos3:
          appSecret.slice(-3),
        horario_servidor:
          new Date().toISOString(),
        timestamp_unix:
          Math.floor(Date.now() / 1000)
      });
    }

    // Gera o link de autorização
    if (acao === 'gerar_link_autorizacao') {
      const { clienteId } = params;

      if (!clienteId) {
        return res.status(400).json({
          erro: 'clienteId é obrigatório.'
        });
      }

      const url =
        `${AUTH_URL}/oauth/authorize?` +
        `app_key=${appKey}` +
        `&state=${encodeURIComponent(clienteId)}` +
        `&redirect_uri=${encodeURIComponent(
          redirectUri
        )}`;

      return res.status(200).json({
        ok: true,
        url
      });
    }

    // Troca o code pelo access_token
    if (acao === 'trocar_codigo') {
      const { code } = params;

      if (!code) {
        return res.status(400).json({
          erro: 'code é obrigatório.'
        });
      }

      const resp = await fetch(
        `${AUTH_URL}/api/v2/token/get?` +
        `app_key=${appKey}` +
        `&app_secret=${appSecret}` +
        `&auth_code=${code}` +
        `&grant_type=authorized_code`
      );

      const data = await resp.json();

      if (data.code !== 0) {
        return res.status(200).json({
          ok: false,
          erro:
            data.message ||
            'Falha ao trocar o código.'
        });
      }

      const accessToken =
        data.data.access_token;

      // Busca as lojas autorizadas
      const lojas = await chamarTiktok(
        '/authorization/202309/shops',
        {},
        'GET',
        null,
        accessToken
      );

      const listaLojas =
        lojas?.data?.shops || [];

      // DIAGNÓSTICO:
      // Se não encontrar loja, mostra a resposta
      // da TikTok sem expor access_token ou app_secret.
      if (!listaLojas.length) {
        return res.status(200).json({
          ok: false,
          etapa: 'buscar_lojas',

          erro:
            'Token obtido, mas nenhuma loja autorizada foi encontrada.',

          token_obtido: !!accessToken,

          token_expira_em:
            data.data.access_token_expire_in ||
            null,

          granted_scopes:
            data.data.granted_scopes ||
            data.data.scope ||
            [],

          user_id:
            data.data.user_id ||
            null,

          resposta_tiktok_lojas: {
            http_status:
              lojas?.http_status ?? null,

            code:
              lojas?.code ?? null,

            message:
              lojas?.message ?? null,

            request_id:
              lojas?.request_id ?? null,

            data: lojas?.data
              ? {
                  shops_count:
                    Array.isArray(
                      lojas.data.shops
                    )
                      ? lojas.data.shops.length
                      : 0,

                  has_shops_field:
                    Object.prototype.hasOwnProperty.call(
                      lojas.data,
                      'shops'
                    )
                }
              : null
          }
        });
      }

      const loja = listaLojas[0];

      return res.status(200).json({
        ok: true,

        // Credenciais
        access_token: accessToken,

        refresh_token:
          data.data.refresh_token,

        expires_in:
          data.data.access_token_expire_in,

        // Diagnóstico
        granted_scopes:
          data.data.granted_scopes ||
          data.data.scope ||
          [],

        user_id:
          data.data.user_id ||
          null,

        // Loja
        shop_id: loja.id,

        shop_cipher: loja.cipher,

        shop_name: loja.name
      });
    }

    // Busca o GMV
    if (acao === 'buscar_gmv') {
      const {
        access_token,
        shop_id,
        shop_cipher,
        data_inicio,
        data_fim,
        __debug_sign
      } = params;

      if (
        !access_token ||
        !shop_id ||
        !shop_cipher
      ) {
        return res.status(400).json({
          erro:
            'access_token, shop_id e shop_cipher são obrigatórios.'
        });
      }

      const path =
        '/order/202309/orders/search';

      const timeFromTotal =
        Math.floor(
          new Date(data_inicio).getTime() /
            1000
        );

      const timeToTotal =
        Math.floor(
          new Date(data_fim).getTime() /
            1000
        );

      let gmvTotal = 0;
      let totalPedidos = 0;
      let pageToken = '';
      let seguir = true;

      while (seguir) {
        const queryParams = {
          shop_id,
          shop_cipher,
          page_size: '50',

          ...(pageToken
            ? { page_token: pageToken }
            : {}),

          ...(__debug_sign
            ? { __debug_sign: '1' }
            : {})
        };

        const bodyBusca = {
          create_time_ge:
            timeFromTotal,

          create_time_lt:
            timeToTotal
        };

        const resultado =
          await chamarTiktok(
            path,
            queryParams,
            'POST',
            bodyBusca,
            access_token
          );

        if (__debug_sign) {
          return res
            .status(200)
            .json(resultado);
        }

        if (resultado.code !== 0) {
          return res.status(200).json({
            ok: false,
            erro:
              resultado.message ||
              'Erro ao buscar pedidos.'
          });
        }

        const pedidos =
          resultado.data?.orders || [];

        pedidos.forEach(p => {
          gmvTotal += Number(
            p.payment?.total_amount || 0
          );

          totalPedidos++;
        });

        pageToken =
          resultado.data
            ?.next_page_token || '';

        seguir = !!pageToken;
      }

      return res.status(200).json({
        ok: true,
        gmv: gmvTotal,
        total_pedidos: totalPedidos
      });
    }

    // Cria promoção
    if (acao === 'criar_promocao') {
      const {
        access_token,
        shop_id,
        shop_cipher,
        tipo,
        percentual,
        produtos,
        duracao_dias
      } = params;

      if (
        !access_token ||
        !shop_id ||
        !shop_cipher
      ) {
        return res.status(400).json({
          erro:
            'access_token, shop_id e shop_cipher são obrigatórios.'
        });
      }

      if (
        !produtos ||
        !produtos.length
      ) {
        return res.status(400).json({
          erro:
            'produtos (lista de product_id) é obrigatório.'
        });
      }

      const agora =
        Math.floor(Date.now() / 1000);

      const dias =
        tipo === 'FLASH_SALE'
          ? Math.min(
              duracao_dias || 3,
              3
            )
          : duracao_dias || 90;

      const fim =
        agora +
        dias * 24 * 60 * 60;

      const corpo = {
        title:
          `${
            tipo === 'FLASH_SALE'
              ? 'Oferta Relâmpago'
              : 'Desconto'
          } - LB Marketplace`,

        activity_type: tipo,

        product_level: 'PRODUCT',

        begin_time: agora,

        end_time: fim,

        products:
          produtos.map(p => ({
            product_id:
              p.product_id,

            discount: {
              type:
                'PERCENTAGE_OFF',

              percentage:
                percentual || 5
            }
          }))
      };

      const resultado =
        await chamarTiktok(
          '/promotion/202309/activities',
          {
            shop_id,
            shop_cipher
          },
          'POST',
          corpo,
          access_token
        );

      if (resultado.code !== 0) {
        return res.status(200).json({
          ok: false,

          erro:
            resultado.message ||
            'Erro ao criar promoção.',

          debug: resultado,

          corpoEnviado: corpo
        });
      }

      return res.status(200).json({
        ok: true,

        activity_id:
          resultado.data?.activity_id,

        inicio: agora,

        fim,

        debug: resultado
      });
    }

    return res.status(400).json({
      erro: 'Ação não reconhecida.'
    });

  } catch (e) {
    console.error(e);

    return res.status(500).json({
      erro:
        'Erro interno: ' +
        (e.message || 'desconhecido')
    });
  }
}
