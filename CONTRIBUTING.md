# Contribuindo

1. Abra issue com escopo e caso de uso, sem revelar dados privados.
2. Crie branch própria e mantenha commits atômicos.
3. Inclua testes de regressão adversariais, especialmente de DNS, URLs, TLS e limites.
4. Execute `python -m unittest discover -s tests -v` e `python -m compileall -q src`.
5. Atualize a documentação e a matriz de ameaça quando alterar garantia ou limite.
6. Nunca remova controles de TLS ou permita redes privadas por padrão.
7. As propostas passarão por revisão de código e CI antes do merge.

## Código de conduta

Seja cordial e técnico. Não publique segredos ou amostras contendo dados reais. Siga `CODE_OF_CONDUCT.md`.
