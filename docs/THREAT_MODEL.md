# Modelo de ameaças — CircuitLock v0.1.0

## Ativos e fronteiras de confiança

Atores: aplicação servidora que recebe URL de terceiros, código CircuitLock confiável, resolvedor DNS local, rede, servidor de destino e resposta HTTP. **A URL, as respostas DNS e todo o conteúdo recebido são não confiáveis.** A política é considerada entrada controlada pelo operador da aplicação (não pelo usuário que envia URLs).

**Objetivo:** evitar que o código que utiliza `safe_fetch()` conecte a IPs fora da política, inclusive após resolução DNS ou redirecionamento.

## Controles realizados

| Risco | Controle | Risco residual |
|---|---|---|
| URL contendo credenciais e esquemas incomuns | Parser estrito, HTTPS por padrão, sem userinfo | Sem suporte a protocolos especiais |
| SSRF para rede interna ou metadata | Rejeição de endereços `!is_global`; metadados conhecidos; CIDR apenas por exceção explícita | Falhas de classificação do Python, permissões CIDR excessivas e rotas de rede do host |
| DNS rebinding entre validação e socket | Resolver retorna IPs numéricos; todos são verificados; conexão usa IP numérico aprovado | DNS controla a escolha entre IPs públicos; um IP público pode hospedar serviço malicioso |
| Respostas com IPv4 e IPv6 misturados | Rejeição de **qualquer** IP do conjunto fora da política | DoS por DNS controlado pelo atacante é possível; comportamento intencionalmente conservador |
| IPv4-mapped IPv6 / IPv6 tunneled | Bloqueio de IPv4-mapped, 6to4 e Teredo | Outras topologias de roteamento exigem firewall externo |
| Redirecionamento para rede proibida | Redirecionamento desativado por padrão e revalidação completa por salto | Redirecionamento permitido pode ampliar destinos aceitos pela política |
| HTTP downgrade | HTTPS -> HTTP negado mesmo com HTTP habilitado | HTTP autorizado pelo operador não oferece confidencialidade |
| Certificado TLS errado | `ssl.create_default_context` + SNI e hostname originais | CA local comprometida, ataques no ambiente de execução |
| Exaustão de memória | Teto de bytes por resposta, streaming limitado pelo `read(N+1)` | Sem deadline global; DNS pode bloquear além do timeout do socket |
| Cabeçalhos/cookies secretos encaminhados por redirect | GET/HEAD, lista fixa de headers, nenhum header fornecido pelo atacante | A URL e query originais ainda são enviadas ao servidor de destino |
| Exposição de dados em logs CLI | Não registra URL, query, corpo ou exceção da rede | Logs externos de proxies/servidores podem capturar URLs |
| Arquivo local existente no CLI | Escrita com `O_EXCL`, permissões restritas | Saída pode conter conteúdo malicioso, que não é interpretado pelo projeto |

## Fora do escopo

- Rede do sistema operacional, proxy transparante, firewall, container escape, sandbox, sequestro de CA ou DNS do host.
- Verificação de reputação do domínio, ameaças em arquivos, malware, XSS ou DLP.
- Tráfego gerado por bibliotecas que não chamam `safe_fetch()`.
- Timeouts totais rígidos (incluindo `getaddrinfo`), cache DNS, autenticação e envio de dados POST/PUT.

## Propriedades testadas

Unittest verifica recusa de endereços privados/reservados, DNS misto, túnel IPv6, credenciais na URL, cabeçalhos seguros, redirects locais e para metadata, socket numérico, hostname HTTP original, TLS check_hostname, tamanho, criação exclusiva e erros sem revelar URL.

**Não há auditoria externa** nem exploração ativa de sistemas de terceiros: a suíte de integração usa exclusivamente servidor local criado nos próprios testes.
