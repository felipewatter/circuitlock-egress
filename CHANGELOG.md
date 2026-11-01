# Changelog

## [0.1.0] — 2026-10-31

- Primeira versão pública da biblioteca/CLI CircuitLock de controle de saída HTTP(S).
- Padrões deny-by-default: HTTPS/443, sem redirects, sem CIDRs privados, limite de 2 MiB.
- DNS A/AAAA validado integralmente, socket fixado ao IP aprovado e TLS com hostname original.
- Defesa contra IPv4-mapped IPv6, IPv6 transition, destinos de metadata e respostas DNS misturadas.
- Política JSON de hosts, CIDRs, portas, protocolos e limites, sem duplicatas ou campos desconhecidos.
- CLI com metadados sem URL, download opcional em arquivo novo sem sobrescrita.
- Suíte de testes offline e local, documentação de segurança/arquitetura, GitHub Actions e Dependabot.

**Nota:** versão experimental, não auditada independentemente; requer defesa em profundidade de rede.
