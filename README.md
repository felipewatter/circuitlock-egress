# CircuitLock — Deny-by-default Outbound HTTP(S) Security

**Defesa de saída HTTP(S) para aplicações Python sujeitas a URLs externas não confiáveis.** O CircuitLock é uma biblioteca e CLI sem dependências externas de runtime, orientada a reduzir riscos de **SSRF (Server-Side Request Forgery)**, DNS rebinding, redirecionamentos não validados e consumo excessivo de recursos.

> **Versão 0.1.0 — experimental / não auditada independentemente.** Não constitui firewall, prevenção absoluta de SSRF ou solução de segurança de rede para protocolos diferentes de HTTP(S). **Não habilite redes privadas em produção sem um modelo de autorização específico.**

## Por que é diferente dos outros projetos

O CircuitLock não faz auditoria de dependências, scanning de CVEs, segredo, JWT, assinatura de proveniência ou detecção pós-fato de alterações. Ele aplica **políticas no instante de uma requisição de saída**, antes de abrir uma conexão de rede, para restringir destinos potencialmente perigosos.

A motivação vem das recomendações de [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), e do problema documentado de **DNS rebinding**: verificar um nome e deixar um cliente HTTP resolver o nome novamente cria uma janela TOCTOU. O CircuitLock valida as respostas A/AAAA e cria um socket para o **IP numérico verificado**, mantendo o hostname de origem em TLS (SNI e validação de certificado).

### Características

| Controle | Implementação |
|---|---|
| Protocolo | HTTPS **443** como padrão; HTTP somente se autorizado explicitamente |
| IPs privados e reservados | Bloqueados por padrão via `ipaddress.is_global` |
| IPs de IPv4-mapped IPv6 / 6to4 / Teredo | Rejeitados inclusive com exceções de CIDR |
| DNS rebind / DNS mixed answers | **Todos** os IPs A/AAAA são validados antes do socket, e o socket usa apenas o IP escolhido |
| TLS | `ssl.create_default_context` mantém validação de CA e hostname/SNI originais |
| Redirect | Desativado por padrão; até 5 saltos explicitamente autorizados e revalidados individualmente; downgrade TLS rejeitado |
| Egress policy | Allowlist exata de hosts, portas, esquemas, CIDRs e tetos de recursos |
| Requisições | Somente GET/HEAD, sem corpo ou headers arbitrários, sem autenticação, sem variáveis de proxy |
| Respostas | 2 MiB por padrão; máximo configurável 16 MiB, timeouts por operação e cabeçalhos controlados |
| CLI | Saída de **metadados sem URL e sem corpo**; bytes opcionais em arquivo novo com modo 0600 |
| Testes | Suíte unittest, inclusive com servidor HTTP real local e casos adversariais |

## Instalação

Requer **Python 3.11 ou superior**. Runtime utiliza **somente a biblioteca padrão**.

```bash
git clone https://github.com/felipewatter/circuitlock-egress.git
cd circuitlock-egress
python -m pip install -e .
python -m circuitlock --help
```

A instalação a partir do checkout não significa que o projeto já esteja publicado no PyPI.

## Exemplo rápido, seguro por padrão

```bash
# Somente destinos HTTPS:443 públicos, sem redirects, resposta <= 2 MiB.
circuitlock 'https://example.org/'

# Conteúdo binário é salvo apenas quando solicitado;
# recusa sobrescrever arquivo existente ou link simbólico.
circuitlock 'https://example.org/' --output resultado.bin
```

A saída JSON contém apenas `status`, `bytes`, `sha256`, `redirects`, `host`, `content_type` e `written`. **Não inclui a URL original, query string nem o conteúdo.** O retorno `0` indica que a requisição foi admitida e concluída, não que o conteúdo HTTP é confiável ou que seu status seja 2xx. Erros ou recusas retornam `2`.

### Política como código

Exemplo em [`examples/egress-policy.json`](examples/egress-policy.json):

```json
{
  "allowed_hosts": ["example.org", "api.example.org"],
  "allowed_ports": [443],
  "allowed_schemes": ["https"],
  "max_redirects": 1,
  "max_response_bytes": 1048576,
  "timeout_seconds": 10,
  "max_dns_answers": 16
}
```

```bash
circuitlock 'https://example.org/' --policy examples/egress-policy.json --head
```

- `allowed_hosts`: **exata** e lowercase, não admite curingas.
- `allowed_cidrs`: lista **opcional** de CIDRs não públicos expressamente autorizados. Vazia por padrão. **Evite em ambientes expostos a URLs arbitrárias**; não há substituto para controles de firewall/rede.
- `allowed_schemes`: `https` por padrão; `http` exige opção declarada.
- `allowed_ports`: apenas 443 por padrão.
- `max_redirects`: 0 por padrão; até 5, com validação completa por salto.
- `max_response_bytes`: 2 MiB por padrão; entre 1 e 16 MiB.
- `timeout_seconds`: timeout de socket por operação (1–30 segundos). Não é prazo total de execução, nem garante limite para resolução DNS.
- `max_dns_answers`: até 32 respostas por nome, com rejeição se qualquer resposta violar a política.

**Atenção:** a lista de redes explicitamente permitidas é uma exceção ao bloqueio de endereços não públicos. Esse recurso é destinado a integrações internas **autorizadas** e testes locais; revise-o cuidadosamente antes de deploy.

### Uso como biblioteca

```python
from circuitlock import Policy, safe_fetch, CircuitLockError

policy = Policy(
    allowed_hosts=("example.org",),
    allowed_ports=(443,),
    allowed_schemes=("https",),
    max_redirects=0,
    max_response_bytes=1024 * 1024,
)

try:
    result = safe_fetch("https://example.org/", policy)
    print(result.status, result.size, result.sha256)
except CircuitLockError:
    print("Requisição recusada ou incompleta")
```

O corpo devolvido na biblioteca é armazenado em memória, limitado pelo teto configurado. Nunca registre URLs com tokens na aplicação chamadora. Não concatene cabeçalhos arbitrários, cookies, credenciais ou parâmetros de autenticação com dados fornecidos por terceiros.

## Falha segura e comportamento de segurança

O projeto recusa entradas contendo: esquemas além de HTTP(S), credenciais URL (`user:pass@host`), caracteres de controle/espaços, backslashes, domínios Unicode não normalizados, hostnames locais, URLs com fragmento, hosts fora da allowlist, portas não autorizadas, IPs não públicos sem exceção CIDR, e respostas DNS vazias/incompatíveis.

Quando habilitados, redirects são resolvidos como URLs independentes e passam por nova autorização. Uma resposta redirecionando HTTPS para HTTP é bloqueada. O transporte **não** consulta `HTTP_PROXY` ou `HTTPS_PROXY`; o socket usa exclusivamente o endereço numérico aprovado. TLS continua verificando certificado para o hostname originalmente solicitado.

### Escopo e limites reais

- Nenhuma biblioteca HTTP isolada substitui regras de firewall, isolamento de namespace, IAM ou restrição de serviço metadata no host/cloud.
- O parser bloqueia hostnames Unicode deliberadamente. Domínios IDN só podem ser usados em representação ASCII/punycode com allowlist consciente.
- `ipaddress.is_global` e a tabela de endereços reservados seguem a versão da biblioteca padrão Python em uso; políticas de rede devem ser validadas também no egress gateway.
- **DNS em si não possui prazo absoluto imposto pelo projeto**. Um resolvedor host travado pode ultrapassar `timeout_seconds`; operação deve ser executada num worker com deadline externo.
- `max_response_bytes` é limite de bytes recebidos; **não** valida semanticamente JSON, HTML, imagens, MIME ou conteúdo comprimido.
- A ferramenta não é um gateway HTTP multiusuário, não captura outras bibliotecas de rede do processo e não protege chamadas que não utilizem `safe_fetch()`.
- DNS-redirect, IP policy e timeout não eliminam riscos de comprometimento do host ou de uma CA/registro DNS.
- O protocolo não inclui CONNECT, WebSockets, FTP, gopher, file, protocolos não HTTP(S), cabeçalhos de autenticação, envio de corpos ou reuso de sockets.
- **Proteção de conteúdo não foi prometida:** uma resposta HTTP pode ser nociva mesmo vindo de um destino permitido.

Consulte [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`SECURITY.md`](SECURITY.md) e [`docs/TEST_MATRIX.md`](docs/TEST_MATRIX.md).

## Qualidade e testes

```bash
python -m unittest discover -s tests -v
python -m compileall -q src
python -m pip check
```

GitHub Actions testa versões de Python em Ubuntu, Windows e macOS, sem chamadas a serviços públicos durante os testes (servidor HTTP local apenas). Os workflows usam permissões mínimas e ações fixadas em commit SHA. O Dependabot acompanha GitHub Actions e dependências Python de build.

## Comparação de referências

| Projeto/referência | Relevância para o CircuitLock |
|---|---|
| [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Recomenda validação de IP e DNS, desativação de redirects e controle de saída |
| [vercel-labs/guarded-fetch](https://github.com/vercel-labs/guarded-fetch) | Implementação madura para Node.js usando undici e validação por salto; referência, não código copiado |
| [jonathanong/ssrf-guard](https://github.com/jonathanong/ssrf-guard) | Discussão da defesa contra TOCTOU com endereços pinnable no Node.js |
| [Python ssl](https://docs.python.org/3/library/ssl.html) | Base de configuração TLS segura e validação do hostname |

**O projeto é novo em relação ao portfólio público `felipewatter` consultado.** Isso não implica que a ideia não exista em código aberto: as bibliotecas citadas acima já tratam problemas semelhantes, em outras arquiteturas.

## Licença

**MIT**, © 2026 Felipe Watter. Segurança é um processo contínuo; a versão 0.1.0 não possui auditoria externa independente.
