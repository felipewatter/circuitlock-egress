# Matriz de testes

## Unidade

- `test_policy.py`: defaults, esquema, formato estrito, limites e duplicatas, leitura de arquivo segura.
- `test_address.py`: credenciais, URLs ambíguas, IPv4/IPv6 especiais, endereços DNS não públicos, rebind misto, allowlist e limitação de DNS.
- `test_transport.py`: servidor HTTP de loopback nos testes, redirects, resposta limitada, HEAD, IP fixado e Host correto, CLI com arquivo de saída exclusivo.

## Execução reproduzível

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
python -m pip check
```

O CI do GitHub (`.github/workflows/ci.yml`) executará uma matriz Python 3.11, 3.12, 3.13 e 3.14 em Ubuntu, Windows e macOS. Os testes não fazem consultas DNS ou HTTP externos: somente resolvers simulados e servidores locais.

## Cobertura esperada e limites

Os testes exercitam os controles implementados, **não** certificam resistência universal a SSRF. Testes de execução com certificado TLS real contra uma CA de teste customizada são uma evolução futura e não estão incluídos nesta versão. A verificação de TLS ativa é exercitada por inspeção do contexto seguro, e o código usa `ssl.create_default_context` sem opção para desabilitar validação.
