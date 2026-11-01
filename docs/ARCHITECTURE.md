# Arquitetura e invariantes

```text
  Untrusted URL + Operator-owned Policy
                 |
          Strict URL parser
                 |
    Enforce scheme, host, port
                 |
          DNS A/AAAA lookup
                 |
      Validate ALL IP answers
         reject on any miss
                 |
         Select numeric IP
                 |
       TCP connect to IP ONLY
         HTTP Host preserved
     HTTPS SNI + CA validation
                 |
       HTTP GET / HEAD only
       redirects disabled or
        repeat full pipeline
                 |
       Bounded response read
                 |
       SHA-256 + safe metadata
```

## Invariantes de segurança

1. Nenhum socket é criado até a política aprovar **todas** as respostas DNS do destino (sem fail-open).
2. A conexão usa o IP numérico aprovado, nunca o hostname DNS original para abrir o socket.
3. Em HTTPS, SNI e validação do certificado usam o hostname solicitado, não o IP resolvido.
4. O cliente não utiliza automaticamente proxies de ambiente nem redirects do HTTP client.
5. Redirects permitidos repetem as etapas de validação; HTTPS nunca retorna a HTTP.
6. Nenhum corpo, cookie, cabeçalho personalizado ou credencial é aceito na API pública de transporte.
7. Erros não contêm mensagens do servidor, URLs com query nem stack traces na saída padrão da CLI.
8. Resposta completa só é devolvida se couber no limite configurado; nenhum sucesso parcial.

## Módulos

- `policy.py`: configuração dataclass imutável, política JSON com campos únicos e limite de tamanho, CIDRs canônicos.
- `address.py`: URL parser, DNS resolver, validação global/privada e pinagem do IP escolhido.
- `transport.py`: classes HTTPConnection/HTTPSConnection com socket de IP escolhido, TLS com nome original, validação de redirects e resposta limitada.
- `cli.py`: entrada/salvamento explícitos e saída JSON de metadados, sem conteúdo.
- `errors.py`: hierarquia de exceções com mensagens normalizadas.

## Extensões planejadas

Tempo total por request via execução isolada (para cobrir resolução DNS), métricas agregadas preservando privacidade, integração com políticas de firewall do host, políticas por origem confiável e testes cruzados com TLS local usando CA descartável. Não declarar esses itens implementados até existirem testes demonstrando seu funcionamento.
