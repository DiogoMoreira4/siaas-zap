# siaas-zap

## Plataforma Inteligente Inteligente para a Automação da Deteção de Vulnerabilidades em Aplicações Web

Este trabalho surgiu no contexto da elaboração de uma dissertação do Mestrado de Informática e Gestão (MIG) no ISCTE.

Trabalho realizado por Diogo Moreira, supervisionado pelos Professores Doutores Carlos José Corredoura Serrão e João Pedro Calado Barradas Branco Pavia.

### Instruções (testado no Ubuntu 20.04 "Focal" e Ubuntu 22.04 "Jammy"):

### Instalação:
- Clonar o repositório: https://github.com/DiogoMoreira4/siaas-zap.git;
- Abrir uma linha de comandos na raiz da pasta "siaas-zap";
- Executar o comando "sudo ./setup.sh";
- Executar novamente o script "setup.sh", mas desta vez sem os privilégios root. Comando: "./setup.sh";


### Utilização:
Depois da instalação, podemos verificar que existe um ficheiro targets.ini vazio dentro da pasta "siaas-zap".
Este ficheiro deve ser preenchido com os alvos a analisar, seguindo a estrutura indicada abaixo:

--------------------------------------------------------------------------------

[AppName]

name: AppName (obrigatório)

url: url da aplicação (obrigatório)

username: (obrigatório no caso de querer realizar um scan com autenticação)

password: (obrigatório no caso de querer realizar um scan com autenticação)

loginpage: (obrigatório no caso de querer realizar um scan com autenticação)

---------------------------------------------------------------------------------

Depois de preencher o ficheiro com os targets a analisar é só correr o segunite comando:
- sudo systemctl start zap_manager

Se for necessário parar a anlaise, podemos recorrer ao seguinte comando:
- sudo systemctl stop zap_manager

Quanto aos logs do sistema, cada instancia do ZAP criada irá possuir os seus próprios registos e ficarão armazenados na pasta siaas-zap/instances/instanceX;
Para além dos logs de cada instancia, existirá um ficheiro zap_manager.log na pasta siaas-zap que permite ao utilizador visualizar qual o alvo que está a ser analisado e qual o progresso da análise.

#### Nota: Este módulo precisa do módulo siaas-server a correr simultaneamente, pois é no módulo siaas-server que se encontram as configurações para correr o ZAP e também onde ficarão armazenados os dados das análises efetuadas.
