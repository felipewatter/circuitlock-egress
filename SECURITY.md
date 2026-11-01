# Política de divulgação responsável

Se encontrar uma falha, prefira **GitHub Private Vulnerability Reporting / Security Advisories** do repositório, quando disponível. Não publique segredos, endereços internos ou exemplos que revelem infraestrutura real em issues públicas.

## Suporte e garantias

CircuitLock v0.1.0 é software **experimental, sem auditoria independente**. A API `safe_fetch()` impõe políticas apenas às requisições feitas por ela. Pode falhar fechado por DNS ambíguo, redes não públicas, respostas grandes ou timeouts. A rede deve impor limites adicionais na infraestrutura (firewall/egress proxy).

É obrigatório validar políticas e allowlists em revisão de código. A opção `allowed_cidrs` é poderosa e **reduz o isolamento** quando configurada para redes internas. Nunca aceite políticas como dados fornecidos pelo mesmo usuário não confiável que fornece as URLs.

## Orientações de operação

- Não habilite proxies transparentes ou reescrita de tráfego TCP sem considerar seu efeito sobre a ligação IP validado/socket.
- Restrinja chamadas a GET/HEAD, autenticação e URLs assinadas exigem arquitetura separada.
- Execute em worker isolado com timeout **total externo** (incluindo resolução DNS), cgroups e limite de memória.
- Evite logging de URLs não confiáveis com tokens e jamais imprima query strings completas.
- Mantenha Python atualizado: a classificação `ipaddress.is_global` pode evoluir conforme as tabelas de endereços especiais.
- O projeto não usa bibliotecas de execução externas, mas dependências de build/desenvolvimento precisam ser revisadas.

Leia `docs/THREAT_MODEL.md` para ameaças consideradas e riscos residuais.
