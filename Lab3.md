# Lab 3 - Web Security

No âmbito da **OWASP *Juice Shop***, os desafios escolhidos são os seguintes:
- *Login Bender*
- *Database Schema*
- *GDPR Data Erasure*
- *API-Only XSS*
- *Forged Review*

## SQL Injection

A *Juice Shop* contém diversos desafios relacionados com *SQL Injection*, dos quais se opta por realizar o ***Login Bender***, ***Database Schema*** e ***GDPR Data Erasure***.

### Login Bender

O desafio *Login Bender* consiste em iniciar sessão com a conta do utilizador *Bender*. Este desafio é extremamente similar ao *Login Admin*, sendo apenas necessário encontrar o e-mail correto, ou seja, o e-mail associado ao utilizador *Bender*.

O e-mail `bender@juice-sh.op` pode ser encontrado numa *review* do produto *Banana Juice*, por exemplo.

Para iniciar sessão com o e-mail `bender@juice-sh.op`, basta introduzir no campo de e-mail o valor `bender@juice-sh.op' --` e qualquer valor não vazio como palavra-passe. Desta forma, concretiza-se um ataque de *SQL Injection*, ao comentar a validação de todos os campos posteriores ao endereço de e-mail na *query* SQL associada ao *login*.

A imagem abaixo mostra a conclusão bem-sucedida do desafio.

![Login Bender](/Lab3/images/login-bender.png)

Note-se que deve ser evitada a abordagem mais comum de colocar `OR 1=1` neste ataque de *SQL Injection*, visto que essa *query* retornaria toda a tabela de utilizadores, iniciando a sessão do primeiro elemento/utilizador que, neste caso, é o `admin@juice-sh.op`, pelo que essa abordagem contrariaria o pretendido (`bender@juice-sh.op`).

A vulnerabilidade que permitiu o ataque é a validação imprópria do *input*.

As linhas de código que são responsáveis por esta vulnerabilidade transcrevem-se abaixo, encontrando-se no ficheiro `login.ts`. 

```ts
module.exports = function login () {
    function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
        .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
        }).catch((error: Error) => {
        next(error)
        })
    }
     
    return (req: Request, res: Response, next: NextFunction) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
        .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
            res.status(401).json({
            status: 'totp_token_required',
            data: {
                tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
                })
            }
            })
        } else if (user.data?.id) {
            afterLogin(user, res, next)
        } else {
            res.status(401).send(res.__('Invalid email or password.'))
        }
        }).catch((error: Error) => {
        next(error)
        })
    }
}
```

Na função `login()`, a linha ```models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })``` permite a execução direta de uma *query* SQL, sem qualquer validação ou sanitização do *input* do utilizador.

Uma alternativa que solucionaria esta vulnerabilidade seria fazer *bind* aos parâmetros da *query*, modificando a linha de código para ```models.sequelize.query(`SELECT * FROM Users WHERE email = $mail AND password = $pass AND deletedAt IS NULL`, { bind: { mail: req.body.email, pass: security.hash(req.body.password) }, model: models.User, plain: true })```. Desta forma, a *query* tornar-se-ia equivalente a um *prepared statement*, evitando adulterações na sintaxe através da introdução de *inputs* maliciosos por parte do utilizador, sendo fixada/preparada antes de qualquer *input* lhe ser fornecido.

O analisador estático automatizado ***SonarCloud*** deteta corretamente esta vulnerabilidade, identificando a linha de código em questão.

![SonarCloud](/Lab3/images/sonarcloud-1-1.png)

Efetivamente, o ***SonarCloud*** sugere a alteração do código para não construir a *query* SQL diretamente a partir de dados controlados pelo utilizador, sem a validação adequada.

O ***SonarCloud*** é capaz de detetar esta vulnerabilidade porque, internamente, realiza *taint analysis*, identificando como fonte o pedido HTTP proveniente do utilizador e como destino a invocação à base de dados, tal como sugere a imagem abaixo.

![SonarCloud](/Lab3/images/sonarcloud-1-2.png)

Como não existe qualquer sanitização do *input* do utilizador desde a origem até ao destino, o ***SonarCloud*** identifica esta linha de codigo como uma potencial vulnerabilidade.

Após corrigir o código e executar novamente a análise do ***SonarCloud***, o analisador já não reporta a vulnerabilidade anteriormente existente, considerando-a resolvida, como se verifica na imagem abaixo.

![SonarCloud](/Lab3/images/sonarcloud-1-3.png)

Isto sucede porque o novo código resolve o problema anterior ao fazer *bind* do *input* do utilizador à *query*, pelo que o ***SonarCloud*** passa a considerar a *query* SQL como segura, por não poder ser manipulada ou adulterada com base no *input* controlado pelo utilizador. Assim, deixa de existir uma vulnerabilidade nesta linha de código.

### Database Schema

O desafio *Database Schema* passa por exfiltrar todo o esquema definido para a base dados através de *SQL Injection*. Este desafio é semelhante ao anterior, mas requer inferir alguma informação sobre a base de dados de maneira a atacar a página de pesquisa.

Ao usar a ferramenta de análise dinâmica ***Burp Suite*** para controlar os pedidos HTTP, verifica-se que as submissões na barra de pesquisa levam à execução de uma *query* SQL possivelmente vulnerável. O ***Burp Suite*** permite utilizar a funcionalidade de *repeater* de maneira a repetir o pedido HTTP GET associado à barra de pesquisa, mas com um *payload* específico, na tentativa de manipular o resultado a obter.

O pedido HTTP em causa é o seguinte: `GET /rest/products/search?q`.

Para tentar perceber se a *query* não está, efetivamente, a ser sanitizada - pelo que pode ser manipulada - seguem-se as seguintes etapas:

1. Ao pesquisar por `banana`, surgem resultados;
2. A pesquisa por `banana'` origina erros na resposta, o que mostra que o *input* não é devidamente sanitizado.

Ora, para se obter o esquema da base de dados, o pedido HTTP deve ser semelhante a `SELECT sql FROM sqlite_master`. Assim, se for possível manipular a pesquisa para ser realizada a operação de união (`UNION`) com esta *query*, o valor retornado deverá ser o esquema da base de dados, tal como pretendido.

Nesse sentido, experimenta-se enviar o pedido HTTP `GET /rest/products/search?q=banana'--`, que dá erro, visto que existe um erro no fecho/emparelhamento dos parêntesis da *query* SQL, pelo que o *input* deve ter de ser alterado. Nesse caso, o objetivo é enviar um pedido com a estrutura `GET /rest/products/search?q=banana'))[...]--`.

Assim, envia-se o pedido `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20%20FROM%20sqlite_master-`, contendo a *query* pretendida, no qual os valores `%20` representam espaços, codificados para URL. Este pedido retorna o erro exposto abaixo.

```json
"error": {
    "message": "SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns",
    "stack": "Error: SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns",
    "errno": 1,
    "code": "SQLITE_ERROR",
    "sql": "SELECT * FROM Products WHERE ((name LIKE '%banana')) UNION SELECT * FROM sqlite_master--%' OR description LIKE '%banana')) UNION SELECT * FROM sqlite_master--%') AND deletedAt IS NULL) ORDER BY name"
}
```

Deste modo, percebe-se que os operandos da operação de união não têm o mesmo tamanho, pelo que é necessário descobrir qual é esse número. Através de tentativas por força-bruta, é facilmente percetível que o tamanho correto é obtido com o pedido `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20,null,null,null,null%20FROM%20sqlite_master--`.

Assim, chega-se ao pedido HTTP `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20sql,2,3,4,5,6,7,8,9%20FROM%20sqlite_master--`, que retorna o resultado pretendido. Neste caso, para ser bem-sucedido, o `SELECT` requer mais oito campos (`2,3,4,5,6,7,8,9`), que têm de ter valor não nulo de maneira a serem corretamente mapeados nas colunas da *query* à tabela `sqlite_master`.

Por isso, o desafio considera-se bem-sucedido.

Tal como anteriormente, a vulnerabilidade que viabiliza este ataque é a validação inadequada do *input* do utilizador.

Em particular, as linhas de código responsáveis são as seguintes, pertencentes ao ficheiro `search.ts`.

```ts
module.exports = function searchProducts () {
    return (req: Request, res: Response, next: NextFunction) => {
        let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
        criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
        models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
            .then(([products]: any) => {
                const dataString = JSON.stringify(products)
                for (let i = 0; i < products.length; i++) {
                    products[i].name = req.__(products[i].name)
                    products[i].description = req.__(products[i].description)
                }
                res.json(utils.queryResultToJson(products))
            }).catch((error: ErrorWithParent) => {
                next(error.parent)
            })
    }
}
```

Na função `searchProducts()`, a linha ```models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)``` permite a manipulação da *query* SQL a executar, ao não efetuar qualquer processo de verificação nem de sanitização do *input* introduzido em `criteria`.

Deste modo, uma possibilidade que resolveria esta vulnerabilidade consiste em utilizar o mecanismo de *binding* da linguagem para criar um *prepared statement* com a *query* a executar. Em concreto, o código deveria passar a ```models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%:criteria%' OR description LIKE '%:criteria%') AND deletedAt IS NULL) ORDER BY name`, { replacements: { criteria } } )```.  Assim, previne-se a possibilidade de manipulação da sintaxe da *query* através da submissão de *inputs* indevidos pelo utilizador, estabelecendo a execução pretendida previamente à entrada de qualquer *input*.

O ***SonarCloud*** - enquanto analisador estático automatizado - identifica corretamente esta vulnerabilidade, na linha de código correspondente.

![SonarCloud](/Lab3/images/sonarcloud-2-1.png)

Tal como anteriormente, o ***SonarCloud*** instrui o Engenheiro de *Software* a modificar o código no sentido de não construir a *query* SQL de forma direta a partir do *input* controlado pelo utilizador, sugerindo que os dados sejam validados e sanitizados previamente.

Igualmente, esta deteção do ***SonarCloud*** provém da sua capacidade de realizar *taint analysis*, através da qual o pedido HTTP efetuado pelo utilizador é considerado a origem dos dados, sendo o destino a chamada à base de dados, como se verifica na seguinte imagem.

![SonarCloud](/Lab3/images/sonarcloud-2-2.png)

Visto que o *input* do utilizador é passado desde a origem até ao destino sem ser ser submetido a qualquer processo de sanitização/validação, o ***SonarCloud*** destaca a falha de segurança presente no código.

Depois de alterar o código para seguir a recomendação sugerida, o ***SonarCloud*** deixa de reportar a vulnerabilidade que identificava previamente, pelo que considera o novo código seguro. Este facto observa-se na captura de ecrã seguinte.

![SonarCloud](/Lab3/images/sonarcloud-2-3.png)

Isto acontece porque, como o novo código prepara a *query* à base de dados e limita o âmbito que o *input* do utilizador pode afetar aos campos estritamente necessários, a *query* SQL passa a ser segura, visto que deixa de poder ser manipulada pelo utilizador. Assim sendo, o ***SonarCloud*** já não reporta a falha de segurança. 

### GDPR Data Erasure

O desafio *GDPR Data Erasure* tem como objetivo iniciar sessão com a conta do *Chris*, apesar de o utilizador ter (supostamente) sido eliminado. Este desafio não só está relacionado com ambos os anteriores, mas também vai para além das vulnerabilidades de *SQL Injection*, ao ponto de poder ser atribuído à falta de conformidade com o Regulamento Geral de Proteção de Dados (GDPR) no processo de eliminação de dados.

A técnica utilizada anteriormente no desafio *Database Schema* pode ser repetida para pesquisar pelo e-mail e nome do utilizador *Chris*, bem como a data de eliminação da conta. Assim, envia-se o pedido HTTP `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20deletedAt,username,email,1,2,3,4,5,6%20FROM%20Users--`. Deste modo, obtêm-se os campos `username`, `email` e `deletedAt` de todos os utilizadores registados na *Juice Shop*, encontrando-se facilmente o e-mail do *Chris* através de uma pesquisa: `chris.pike@juice-sh.op`.

De forma análoga ao desafio *Login Bender*, é possível iniciar sessão na conta do *Chris* utilizando o e-mail `chris.pike@juice-sh.op' --` e qualquer valor não nulo como palavra-passe.

A imagem seguinte evidencia o desafio concluído com sucesso.

![GDPR Data Erasure](/Lab3/images/GDPR-data-erasure.png)

De modo idêntico aos casos anteriores, a vulnerabilidade que possibilita a execução deste ataque é a validação incorreta do *input* do utilizador - para concretizar *SQL Injection* -, bem como, desta vez, a falta de cumprimento dos requisitos de conformidade do GDPR.

O código responsável por esta vulnerabilidade encontra-se nas linhas abaixo, dos ficheiros `dataErasure.ts` e `privacyRequests.ts`, respetivamente.

```ts
router.post('/', async (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): Promise<void> => {
    const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
    }

    try {
        await PrivacyRequestModel.create({
            UserId: loggedInUser.data.id,
            deletionRequested: true
        })
    ...
    }
}
```

```ts
const PrivacyRequestModelInit = (sequelize: Sequelize) => {
  PrivacyRequestModel.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      UserId: {
        type: DataTypes.INTEGER
      },
      deletionRequested: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      tableName: 'PrivacyRequests',
      sequelize
    }
  )
}
```

O primeiro excerto de código mostra que as submissões de pedidos de eliminação de dados de acordo com o GDPR originam a criação de um objeto da classe `PrivacyRequestModel`, com o atributo `deletionRequested` definido como `true`. No segundo bloco de código, verifica-se que a criação deste objeto com um pedido de privacidade não concretiza qualquer eliminação na base de dados, pelo que o utilizador que efetua a solicitação nunca é, efetivamente, eliminado.

Assim, existe uma falha de conformidade com o GDPR que pode ser explorada por ataques que aproveitem a já explicada falha de *SQL Injection*. Ou seja, este caso combina uma vulnerabilidade técnica - validação inadequada do *input* do utilizador - com uma falha de *business logic*, que consiste no incumprimento do GDPR, isto é, na efetiva eliminação do utilizador.

De maneira a corrigir esta falha lógica, o utilizador deveria ser efetivamente eliminado após submeter o pedido no formulário adequado, sendo que isto implicaria efetuar operações na base de dados. Assim, são várias as mudanças necessárias na lógica do sistema para solucionar este problema, mas que, em código, se podem resumir à adição das linhas seguintes.

```ts
    const userId = loggedInUser.data.id
    await UserModel.destroy({ where: { id: userId } })
```

Note-se que, além disto, a base de dados deve estar configurada adequadamente para lidar com a eliminação de utilizadores, tomando as ações corretas através de operações `ON CASCADE`. Se, por quaisquer motivos legais, os dados do utilizador não puderem ser eliminados durante um determinado período de tempo, devem ser definidas todas as validações/verificações necessárias para impedir que esses utilizadores que solicitaram a própria eliminação não sejam capazes de realizar qualquer ação, nomeadamente iniciar sessão, como foi o caso.

Sendo esta uma vulnerabilidade de *business logic*, o analisador estático automatizado ***SonarCloud*** não é capaz de a detetar, nem no ficheiro `dataErasure.ts`, nem em `privacyRequests.ts`. Isto sucede precisamente porque, no código, não existe qualquer erro ou falha de implementação, mas sim um erro lógico de funcionalidade inadequada, que não pode ser detetado por analisadores automatizados estáticos, como é o caso do ***SonarCloud***, visto que estas ferramentas não têm informação suficiente para determinar quais as funcionalidades pretendidas pelo Engenheiro de *Software*, pelo que não têm forma de as comparar com a implementação concreta real.

Assim sendo, não é pertinente nem aplicável corrigir o código para repetir a análise, dado que o analisador já não a deteta na primeira instância, ou seja, quando está presente, pelo que é esperado que assim permaneça após a retificação do código.

---

A classe de vulnerabilidades geral associada a este grupo de três desafios é a validação imprópria do *input* que, neste caso em concreto, se materializa sob a forma de *SQL Injections*. 

A *Common Weakness Enumeration* (CWE) relevante associada é a [***CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')***](https://cwe.mitre.org/data/definitions/89.html). Ou seja, a aplicação constrói comandos SQL usando *input* influenciado ou introduzido pelo utilizador, sem o neutralizar corretamente, o que permite que alguns elementos específicos (como `'` ou `--`) modifiquem o comando SQL pretendido. Desta forma, a *query* SQL gerada pelo programa pode ser modificada pelo utilizador de forma indevida, levando a que os *inputs* não sejam interpretados como seria expectável.

A imagem abaixo ilustra isto mesmo.

![SQL Injection](/Lab3/images/sql-injection.png)

A possibilidade de explorar esta vulnerabilidade tem impactos extremamente diversificados, que podem abranger a confidencialidade, integridade, disponibilidade, autenticação e controlo de acessos do sistema. Em particular, é possível executar código ou comandos de forma não autorizada, ler ou modificar dados indevidamente e contornar os mecanismos de proteção de maneira a ganhar privilégios ou assumir identidades.

A estratégia mais comum para solucionar esta classe de vulnerabilidades passa por construir *prepared statements*, isto é, pré-processar as *queries* SQL de modo que as variáveis de *input* controlado pelo utilizador estejam vinculadas a determinados campos da *query*, não permitindo a sua manipulação. Esta estratégia é extremamente simples e eficaz, tendo ainda a vantagem de poder aumentar o desempenho do sistema, pelo que é uma solução evidente para evitar este tipo de problemas.

Além disso, existe ainda a possibilidade de utilizar bibliotecas/*frameworks* *Object Relation Mapping*, alinhando o código de programação com as estruturas de bases de dados e tratando as *queries* como chamadas a métodos de classes/objetos, o que impossibilita o utilizador de manipular os comandos a executar.

No mínimo - e de forma mais geral/transversal a outras vulnerabilidades -, deve ser, pelo menos, validado adequadamente o *input*, assumindo que qualquer *input* proveniente do utilizador pode ser malicioso. Assim, deve ser usada uma *whitelist* de *inputs* permitidos, que garantidamente não são capazes contornar os mecanismos de segurança. Deste modo, rejeita-se qualquer valor de *input* que não pertença a esta lista, assegurando o correto funcionamento do sistema, em termos de segurança. É igualmente recomendável que as mensagens de erro para o utilizador não sejam tão informativas como nestes desafios, de maneira a minimizar a informação fornecida a atores potencialmente maliciosos, dificultando eventuais ataques.

## Cross-Site Scripting (XSS)

O desafio escolhido relativo a *Cross-Site Scripting* (XSS) é o ***API-Only XSS***.

### API-Only XSS

No desafio *API-Only XSS*, o pretendido é realizar um ataque de XSS persistente/armazenado com `<iframe src="javascript:alert('xss')>` sem utilizar o *frontend* da aplicação *web*. Assim, pretende-se que o cliente chame métodos da API não disponíveis através da interface *web*, de maneira a armazenar dados maliciosos na base de dados, capazes de afetar futuros pedidos.

O objetivo deste desafio prende-se em perceber como fazer uso da API da aplicação *web* para executar o *payload* pretendido. Ao explorar o *site* através do *browser*, monitorizando os pedidos com o ***Burp Suite***, encontram-se facilmente algumas APIs, como `/Users`, `Products`, `Challenges` e `Quantitys`, entre outras. A imagem abaixo demonstra isto mesmo.

![API-Only XSS](/Lab3/images/api-only-xss-1.png)

Idealmente, pesquisam-se APIs que contenham um campo de autorização (`auth-key` ou `key`, por exemplo), de maneira a compreender se este campo é necessário para efetuar pedidos. Assim, identifica-se o campo `Authorization`, que se pode tentar aproveitar para realizar pedidos para o *endpoint* `/api/Quantitys`. Mostra-se abaixo um excerto de um pedido.

```
GET /api/Quantitys/ HTTP/1.1
Host: localhost:3000
sec-ch-ua-platform: "Linux"
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjAsInVzZXJuYW1lIjoiU21pbGluU3RhbiIsImVtYWlsIjoic3RhbkBqdWljZS1zaC5vcCIsInBhc3N3b3JkIjoiZTkwNDhhM2Y0M2RkNWUwOTRlZjczM2YzYmQ4OGVhNjQiLCJyb2xlIjoiZGVsdXhlIiwiZGVsdXhlVG9rZW4iOiI4ZjcwZTBmNGIwNTY4NWVmZmYxYWI5NzllOGY1ZDdlMzk4NTAzNjkzMDliYjIwNmMyYWQzZjdkNTFhMWY0ZTM5IiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzLzIwLmpwZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNS0wNC0xNiAxNDozNToxOS43MTIgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNS0wNC0xNiAxNDozNToxOS43MTIgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzQ0ODE3OTU5fQ.AJZ9nh6oUGEKqKLd0E2bNh6mDfzbri3mlrg4coLNseDFBKdzJuoupkXfHPkfvLQax4qvmwlh1igO4mYpbr9P4ArilnkfOsD6dE6288UO98IzPk5aD1KFQLnWF6GlOp5OjbjBfVkQoC1uGeU5Z-CWCX1vLt6AzyYbisVCNi3yU3M
```

Para averiguar se, com o mesmo campo de autorização, é possível realizar pedidos com sucesso a outro *endpoint*, altera-se `Quantitys` por `Products`, obtendo-se o resultado exposto abaixo.

![API-Only XSS](/Lab3/images/api-only-xss-2.png)

Deste modo, obtém-se uma lista de todos os produtos, demonstrando que o pedido foi bem-sucedido.

Ao realizar um pedido HTTP OPTIONS - no sentido de identificar todos os verbos HTTP válidos para o *endpoint* em questão -, obtém-se o seguinte resultado.

![API-Only XSS](/Lab3/images/api-only-xss-3.png)

Ou seja, é possível realizar pedidos ao *endpoint* `/api/Products` utilizando os métodos GET, HEAD, PUT, PATCH, POST e DELETE.

A abordagem inicial passa por utilizar o método HTTP PUT, com o qual se verifica que um pedido a `/api/Products/id` - substituindo o campo `id` por um número arbitrário - retorna uma resposta `200 OK`, indicando sucesso.

No entanto, a tentativa de utilizar esta abordagem para alterar a descrição do produto *Orange Juice* não é bem-sucedida, visto que o conteúdo do mesmo permanece inalterado, apesar de a resposta ser `200 OK`. Isto provavelmente deve-se ao facto de um utilizador normal, isto é, não administrador, não ter permissões suficientes/necessárias para alterar um produto.

Tendo em conta que o campo `Authorization` contém um JSON *web token* - reconhecido por começar por `ey` - associado à conta do utilizador autenticado, deve ser essa a razão pela qual não é possivel alterar o conteúdo do produto. Assim, pode tentar-se descobrir o *token* da conta com permissões de administrador (`admin@juice-sh.op`), aproveitando as abordagens anteriores e o ***Burp Suite***.

Ao tentar enviar um pedido HTTP PUT com o JSON *web token* do administrador, continua a obter-se o mesmo resultado de sucesso, mas sem alteração do conteúdo, o que indicia que algo ainda está em falta. Efetivamente, ao acrescentar o *header* `Content-Type: application/json` ao pedido HTTP enviado, o resultado já vai ao encontro do esperado, alterando a descrição do produto.

Assim sendo, basta mudar a descrição enviada para utilizar o *payload* fornecido, concretizando isto no seguinte pedido HTTP (truncado).

```
PUT /api/Products/2 HTTP/1.1
Host: localhost:3000
sec-ch-ua-platform: "Linux"
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDQtMTYgMTQ6MzU6MTkuNzAzICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDQtMTYgMTQ6MzU6MTkuNzAzICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc0NDgxOTgxOX0.qmu6u9tO_jROR80xMNpMayXDVldXkqv5FvZk1rodRKqOnS1qj7yOs0QGPB2W1mi1bG7DvaNc7CMzspsqd711NQk8-ncxIOYP9DAbA7i31jqSndsC99Mtp3iiawtCHVI8N9IRIbmDk3UcSOZJtsmUy3tOO48Wwqxt6tiNPZrc4WM
Content-Type: application/json

{"description":"<iframe src=\"javascript:alert(`xss`)\">"}
```

Deste modo, conclui-se o desafio com sucesso.

Assim como nos casos anteriores, a falha de segurança que permite a concretização deste ataque é a errada validação do *input* enviado pelo utilizador, neste caso nos pedidos à API.

A função que contém o código vulnerável encontra-se abaixo, no ficheiro `main.js`.

```ts
ngAfterViewInit () {
    const products = this.productService.search('')
    const quantities = this.quantityService.getAll()
    forkJoin([quantities, products]).subscribe(([quantities, products]) => {
        const dataTable: TableEntry[] = []
        this.tableData = products
        this.trustProductDescription(products)
        for (const product of products) {
            dataTable.push({
                name: product.name,
                price: product.price,
                deluxePrice: product.deluxePrice,
                id: product.id,
                image: product.image,
                description: product.description
            })
        }
        for (const quantity of quantities) {
            const entry = dataTable.find((dataTableEntry) => {
                return dataTableEntry.id === quantity.ProductId
            })
            if (entry === undefined) {
                continue
            }
            entry.quantity = quantity.quantity
        }
        this.dataSource = new MatTableDataSource<TableEntry>(dataTable)
        for (let i = 1; i <= Math.ceil(this.dataSource.data.length / 12); i++) {
            this.pageSizeOptions.push(i * 12)
        }
        this.paginator.pageSizeOptions = this.pageSizeOptions
        this.dataSource.paginator = this.paginator
        this.gridDataSource = this.dataSource.connect()
        this.resultsLength = this.dataSource.data.length
        this.filterTable()
        this.routerSubscription = this.router.events.subscribe(() => {
            this.filterTable()
        })
        if (window.innerWidth < 2600) {
            this.breakpoint = 4
            if (window.innerWidth < 1740) {
                this.breakpoint = 3
                if (window.innerWidth < 1280) {
                    this.breakpoint = 2
                    if (window.innerWidth < 850) {
                        this.breakpoint = 1
                    }
                }
            }
        } else {
            this.breakpoint = 6
        }
        this.cdRef.detectChanges()
    }, (err) => { console.log(err) })
}
    
trustProductDescription (tableData: any[]) {
    for (let i = 0; i < tableData.length; i++) {
        tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
    }
}
```

Em concreto, a linha `tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)` contorna a validação do *input*, pelo que deve ser removida.

Assim, a forma correta de corrigir esta vulnerabilidade passa precisamente por remover a função `trustProductDescription()`, para que a descrição do produto seja adequadamente validada. Note-se, todavia, que, neste caso, o XSS é também uma consequência da aplicação incorreta do mecanismo de autorização, visto que os utilizadores nunca deveriam ter permissões para alterar descrições de produtos.

Portanto, o código acima exposto deveria deixar de conter a função `trustProductDescription()`, passando ao seguinte.

```ts
ngAfterViewInit () {
    const products = this.productService.search('')
    const quantities = this.quantityService.getAll()
    forkJoin([quantities, products]).subscribe(([quantities, products]) => {
        const dataTable: TableEntry[] = []
        this.tableData = products
        for (const product of products) {
            dataTable.push({
                name: product.name,
                price: product.price,
                deluxePrice: product.deluxePrice,
                id: product.id,
                image: product.image,
                description: product.description
            })
        }
        for (const quantity of quantities) {
            const entry = dataTable.find((dataTableEntry) => {
                return dataTableEntry.id === quantity.ProductId
            })
            if (entry === undefined) {
                continue
            }
            entry.quantity = quantity.quantity
        }
        this.dataSource = new MatTableDataSource<TableEntry>(dataTable)
        for (let i = 1; i <= Math.ceil(this.dataSource.data.length / 12); i++) {
            this.pageSizeOptions.push(i * 12)
        }
        this.paginator.pageSizeOptions = this.pageSizeOptions
        this.dataSource.paginator = this.paginator
        this.gridDataSource = this.dataSource.connect()
        this.resultsLength = this.dataSource.data.length
        this.filterTable()
        this.routerSubscription = this.router.events.subscribe(() => {
            this.filterTable()
        })
        if (window.innerWidth < 2600) {
            this.breakpoint = 4
            if (window.innerWidth < 1740) {
                this.breakpoint = 3
                if (window.innerWidth < 1280) {
                    this.breakpoint = 2
                    if (window.innerWidth < 850) {
                        this.breakpoint = 1
                    }
                }
            }
        } else {
            this.breakpoint = 6
        }
        this.cdRef.detectChanges()
    }, (err) => { console.log(err) })
}
```

Neste caso, não foi possível executar o ***SonarCloud***, visto que o código-fonte exposto após a conclusão do desafio não se encontra disponível no repositório associado à *Juice Shop*.

No entanto, ao ser chamada a função `bypassSecurityTrustHtml()`, seria expectável que o ***SonarCloud***, enquanto ferramenta de análise estática, fosse capaz de identificar corretamente a vulnerabilidade. Este comportamento dever-se-ia ao facto de a função em causa contrariar as boas práticas de segurança, pelo que deveria constar de uma lista interna da ferramenta de funções que, quando utilizadas, devessem suscitar um alerta.

Assim sendo, após a aplicação da respetiva correção, seria expectável que o ***SonarCloud*** deixasse de reportar a vulnerabilidade, visto que deixaria de existir uma chamada à função `bypassSecurityTrustHtml()`, o que já não levantaria qualquer alerta de segurança.

---

O grupo de vulnerabilidades no qual este desafio se insere é a validação imprópria do *input*, que pode ser enviado ao servidor e ainda armazenado na base de dados do mesmo.

A CWE mais pertinente associadas a este caso é a [***CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')***](https://cwe.mitre.org/data/definitions/79.html), mas também [***CWE-116: Improper Encoding or Escaping of Output***](https://cwe.mitre.org/data/definitions/116.html) e [***CWE-20: Improper Input Validation***](https://cwe.mitre.org/data/definitions/20.html), de forma mais geral. Em concreto, a CWE 79 representa a situação na qual o produto neutraliza incorretamente o *input* do utilizador antes de o colocar como *output* numa página *web* apresentada a outros utilizadores, permitindo a materialização de ataques de XSS, neste caso persistente/armazenado.

A imagem seguinte exemplifica este tipo de ataques.

![Cross-Site Scripting](/Lab3/images/cross-site-scripting.png)

Os impactos desta vulnerabilidade podem afetar a confidencialidade, integridade, disponibilidade e controlo de acessos do sistema. Mais concretamente, é possível executar código/comandos de forma não autorizada (como foi o caso), ler dados aplicacionais e contornar mecanismos de proteção.

O método adequado para a resolução destas vulnerabilidades consiste em realizar uma validação correta do *input* do utilizador, neutralizando-o e sanitizando-o de maneira a impedir manipulações indevidas que levam a desviar o comportamento do sistema daquele que seria esperado. A abordagem pode ser tão simples como chamar as funções adequadas da linguagem de programação em causa para tratar o *input*, removendo, codificando ou escapando todos os caracteres potencialmente maliciosos.

A par disto, devem ser utilizados mecanismos estruturados que forcem automaticamente a separação entre código e dados, para garantir a segurança da aplicação. Neste caso em concreto, codificar o *output* disponibilizado aos utilizadores contribuiria também para mitigar a vulnerabilidade, ao impedir a execução do *script*.

Em síntese, a solução para estes casos passa, uma vez mais, por adotar os devidos cuidados e medidas de segurança com todos os *inputs* provenientes do utilizador, que devem sempre ser considerados maliciosos. Assim, através de ferramentas de neutralização, codificação, padronização, escape, sanitização e validação, todos os *inputs* fornecidos ao sistema devem ser tratados.

## Broken Access Control

O desafio selecionado para explorar falhas de *Broken Access Control* é o ***Forged Review***.

### Forged Review

Neste desafio *Forged Review*, pretende-se publicar um comentário de *feedback*/*review* em nome de outro utilizador da plataforma. Nesse sentido, o desafio visa demonstrar que existem pedidos HTTP à REST API que não estão adequadamente protegidos e para os quais não é corretamente validada a autenticação do utilizador.

Em concreto, o utilizador-alvo - em nome do qual deve ser publicado o comentário - é o `bender@juice-sh.op`.

Tendo em conta que não é possível publicar qualquer conteúdo sem estar autenticado, opta-se por começar o processo ao iniciar sessão com uma conta arbitrária, aproveitando a vulnerabilidade de *SQL Injection* anteriormente identificada e exemplificada. A título de exemplo, inicia-se sessão com o utilizador `stan@juice-sh.op`.

Ao utilizar o ***Burp Suite*** para manipular os pedidos HTTP associados à publicação de *feedback*, identifica-se o pedido HTTP em questão como sendo o seguinte, transcrito de forma simplificada.

```
PUT /rest/products/1/reviews
HTTP/1.1
{"message":"I love apples!","author":"stan@juice-sh.op"}
```

Efetivamente, o pedido HTTP contém a *review* enviada em formato JSON, com os campos `message` e `author`. O campo `message` apresenta o conteúdo a publicar, enquanto `author` contém o e-mail do utilizador associado à publicação.

Assim, ao enviar um novo pedido com estes campos modificados, de maneira a enviar outra mensagem em `message` e a conter `bender@juice-sh.op` em `author`, consegue-se facilmente efetuar uma publicação em nome de outro utilizador.

De facto, este ataque explora uma vulnerabilidade de *Broken Access Control*.

O código vulnerável encontra-se abaixo, tendo sido extraído do ficheiro `updateProductReviews.ts`.

```ts
module.exports = function productReviews () {
    return (req: Request, res: Response, next: NextFunction) => {
        const user = security.authenticatedUsers.from(req)
        db.reviewsCollection.update(
            { _id: req.body.id },
            { $set: { message: req.body.message } },
            { multi: true }
        ).then(
            (result: { modified: number, original: Array<{ author: any }> }) => {
                res.json(result)
            }, (err: unknown) => {
                res.status(500).json(err)
            }
        )
    }
}
```

A função `productReviews()` extrai o utilizador autenticado para a variável `user` (`const user = security.authenticatedUsers.from(req)`), mas não utiliza esse valor. Em vez disso, o `id` utilizado para a publicação do conteúdo é enviado no próprio pedido sem validação se pertence ao utilizador autenticado, em `{ _id: req.body.id }`.

Por isso, para resolver esta vulnerabilidade, basta corrigir o código acima identificado, alterando-o para o seguinte, com destaque para a linha `{ _id: req.body.id, author: user.data.email }`.

```ts
module.exports = function productReviews () {
    return (req: Request, res: Response, next: NextFunction) => {
        const user = security.authenticatedUsers.from(req)
        db.reviewsCollection.update(
            { _id: req.body.id, author: user.data.email },
            { $set: { message: req.body.message } },
            { multi: true }
        ).then(
            (result: { modified: number, original: Array<{ author: any }> }) => {
                res.json(result)
            }, (err: unknown) => {
                res.status(500).json(err)
            }
        )
    }
}
```

Desta forma, a porção de código `author: user.data.email` vai buscar a informação do e-mail do utilizador autenticado à sessão atual, garantindo que não é indevidamente submetida informação de outro utilizador. Assim, impede-se facilmente a adulteração de informação publicada na *review*.

A ferramenta de análise estática automatizada ***SonarCloud*** não identifica concretamente esta vulnerabilidade de *Broken Access Control*, ainda que saliente outra falha, na mesma linha de código.

![SonarCloud](/Lab3/images/sonarcloud-5-1.png)

Efetivamente, o ***SonarCloud*** assinala que, no excerto de código mostrado, a *query* à base de dados contém informação diretamente controlada pelo utilizador, pelo que deve ser alterada para ser validada/sanitizada. No entanto, a ferramenta não é capaz de encontrar esta falha de *Broken Access Control*, limitando-se à deteção da possível *SQL Injection*.

Por um lado, o mecanismo interno de *taint analysis* do ***SonarCloud*** é responsável por detetar a falta de validação/sanitização adequada do *input*, proveniente do pedido HTTP do utilizador e destinado à base de dados, conforme se evidencia na imagem abaixo. Por outro lado, a incapacidade em detetar a vulnerabilidade de *Broken Access Control* deve-se ao facto de esta ferramenta não compreender a lógica que deve estar subjacente ao código em causa, pelo que as variáveis e os respetivos valores não têm qualquer significado semântico para a análise.

![SonarCloud](/Lab3/images/sonarcloud-5-2.png)

Assim, o ***SonarCloud*** limita-se a detetar a vulnerabilidade de *SQL Injection*, mas deixa escapar a falha de *Broken Access Control*.

Ao modificar o código conforme explicitado, o ***SonarCloud*** continua com o mesmo comportamento, isto é, identifica a falta de validação do *input*, mas não o *Broken Access Control*, agora resolvido. Este comportamento demonstra-se na imagem abaixo.

![SonarCloud](/Lab3/images/sonarcloud-5-3.png)

Efetivamente, não seria de esperar outro comportamento, visto que a vulnerabilidade corrigida (*Broken Access Control*) já não era, quando existia, detetada pelo ***SonarCloud***, ao contrário da falha que possibilitava ataques de *SQL Injection*, mas que não foi endereçada. Deste modo, a ferramenta de análise estática só podia continuar a detetar este segundo caso, sendo agora a única vulnerabilidade existente na linha de código em causa.

---

Esta vulnerabilidade insere-se num conjunto de falhas classificado como *Broken Access Control*, que consiste no controlo indevido/inadequado dos acessos a determinadas funcionalidades do sistema.

As CWEs que melhor se enquadram neste âmbito são:
1. [***CWE-284: Improper Access Control***](https://cwe.mitre.org/data/definitions/284.html), que consiste em restringir incorretamente o acesso aos recursos do sistema para atores não autorizados;
2. [***CWE-285: Improper Authorization***](https://cwe.mitre.org/data/definitions/285.html), que passa por realizar incorretamente as verificações de autorização quando um ator tenta desempenhar alguma ação e/ou aceder a um recurso;
3. [***CWE-639: Authorization Bypass Through User-Controlled Key***](https://cwe.mitre.org/data/definitions/639.html), ou seja, a funcionalidade de autorização do sistema permitir que um utilizador ganhe acesso aos dados/registos de outro utilizador, ao modificar o valor da chave que identifica esses dados;
4. [***CWE-862: Missing Authorization***](https://cwe.mitre.org/data/definitions/862.html), isto é, o produto não realizar sequer uma verificação de autorização quando um ator tenta aceder a um recurso ou desempenhar alguma ação;
5. [***CWE-269: Improper Privilege Management***](https://cwe.mitre.org/data/definitions/269.html), o que significa que o produto não atribui, modifica, regista ou verifica os privilégios para os atores do sistema, criando uma esfera de controlo mais permissiva do que devido.

As imagens abaixo elucidam estas CWEs.

![Broken Access Control](/Lab3/images/broken-access-control-1.png)

![Broken Access Control](/Lab3/images/broken-access-control-2.png)

Eventuais ataques que explorem estas falhas podem comprometer o controlo de acessos, a confidencialidade, a integridade e a disponibilidade do sistema. Na prática, é indevidamente permitido o contorno de mecanismos de proteção para ganhar privilégios ou assumir identidades, ler e modificar dados aplicacionais, ficheiros e/ou diretórios, bem como consumir recursos e causar falhas.

A abordagem correta para corrigir estas vulnerabilidades passa por, no processo de arquitetura e *design*, garantir que, em cada acesso/ação, o utilizador tem privilégios suficientes para o/a realizar e que a chave utilizada na pesquisa do registo desse mesmo utilizador não é controlável externamente por ele, permitindo a deteção de tentativas de fraude/manipulação. 

Em particular, o produto pode e deve ser dividido em áreas de acesso anónimo, normal, privilegiado ou administrativo, reduzindo a superfície de ataque ao mapear corretamente os papéis e funções dos diferentes tipos de utilizadores com as funcionalidades esperadas para os mesmos. Juntamente a isto, devem ser realizadas verificações de controlo de acessos de acordo com a lógica pretendida, forçando validações do servidor aquando de cada pedido.

Assim, deve ser respeitado o princípio de separação de privilégios e ter especial atenção/cuidado com os campos utilizados para autenticação/autorização, que nunca devem ser controlados pelo utilizador/cliente. A par disto, todas as validações devem ser efetuadas do lado do servidor, de maneira a impedir a sua manipulação ou contorno por parte do cliente.

## Conclusão

Em suma, a tabela seguinte resume os desafios realizados e a informação extraída das ferramentas de análise no que toca à sua capacidade de detetar as vulnerabilidades em questão.

|       **Desafio**       | ***Burp Suite*** | ***SonarCloud*** |
| ----------------------- | ---------------- | ---------------- |
|    ***Login Bender***   |        N/A       |       SIM        |
|  ***Database Schema***  |        SIM       |       SIM        |
| ***GDPR Data Erasure*** |        SIM       |       NÃO        |
|   ***API-Only XSS***    |        SIM       |       N/A        |
|   ***Forged Review***   |        SIM       |       NÃO        |

Assim, conclui-se facilmente que a ferramenta de análise estática ***SonarCloud*** é capaz de detetar vulnerabilidades de injeção devido a validações inadequadas do *input* do utilizador, mas o analisador dinâmico ***Burp Suite*** é mais versátil e eficaz para detetar todo o tipo de vulnerabilidades de diferentes categorias.
