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

Note-se que deve ser evitada a abordagem mais comum de colocar `OR 1=1` neste ataque de *SQL Injection*, visto que essa *query* retornaria toda a tabela de utilizadores, iniciando a sessão do primeiro elemento/utilizador que, neste caso, é o `admin@juice-sh.op`, pelo que esta abordagem contrariaria o pretendido (`bender@juice-sh.op`).

TODO: Describe the general vulnerability class associated with each group of challenges, including relevant CWEs and typical mitigation and fixing strategies.

A vulnerabilidade que permitiu o ataque é a validação imprópria do *input*.

As linhas de código que são responsáveis por esta vulnerabilidade transcrevem-se abaixo.

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

Na função `login()`, a linha ```models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })``` permite a execução direta de uma *query* SQL, sem qualquer validação ou sanitização.

Uma alternativa que solucionaria esta vulnerabilidade seria fazer *bind* aos parâmetros da *query*, modificando a linha de código para ```models.sequelize.query(`SELECT * FROM Users WHERE email = $mail AND password = $pass AND deletedAt IS NULL`, { bind: { mail: req.body.email, pass: security.hash(req.body.password) }, model: models.User, plain: true })```. Desta forma, a *query* tornar-se-ia equivalente a um *prepared statement*, evitando adulterações na sintaxe através da introdução de *inputs* maliciosos por parte do utilizador, sendo fixada/preparada antes de qualquer *input* lhe ser fornecido.

TODO: were the vulnerabilities detected by the automated (static or dynamic) analysers? why do you think that is the case?

TODO: you may patch the code and rerun the analyses. would the analysers no longer report the fixed code as vulnerabilities? why do you think that is the case?

### Database Schema

O desafio *Database Schema* passa por exfiltrar todo o esquema definido para a base dados através de *SQL Injection*. Este desafio é semelhante ao anterior, mas requer inferir alguma informação sobre a base de dados de maneira a atacar a página de pesquisa.

Ao usar o *Burp Suite* para controlar os pedidos HTTP, verifica-se que as submissões na barra de pesquisa levam à execução de uma *query* SQL possivelmente vulnerável. O *Burp Suite* permite utilizar a funcionalidade de *repeater*, de maneira a repetir o pedido HTTP GET associado à barra de pesquisa, mas um *payload* específico, na tentativa de manipular o resultado a obter.

O pedido HTTP em causa é o seguinte: `GET /rest/products/search?q`.

Para tentar perceber se a *query* não está, efetivamente, a ser sanitizada, pelo que pode ser manipulada, seguem-se as etapas descritas:

1. Ao pesquisar por `banana`, surgem resultados;
2. A pesquisa por `banana'` origina erros na resposta, o que mostra que o *input* não é devidamente sanitizado;

Ora, para se obter o esquema da base de dados, o pedido HTTP deve ser semelhante a `SELECT sql FROM sqlite_master`. Assim, se for possível manipular a pesquisa para ser realizada a operação de união (`UNION`) com esta *query*, o valor retornado deverá o esquema da base de dados, tal como pretendido.

Nesse sentido, experimenta-se o seguinte enviar o pedido `GET /rest/products/search?q=banana'--`, que dá erro, visto que existe um erro no fecho/emparelhamento dos parêntesis da *query* SQL, pelo que o *input* deve ter de ser manipulado. Nesse caso, o objetivo é enviar um pedido com a estrutura `GET /rest/products/search?q=banana'))[...]--`.

Assim, envia-se o pedido `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20%20FROM%20sqlite_master-`, contendo a *query* pretendida. Este pedido retorna o erro exposto abaixo.

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

Assim, chega-se ao pedido `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20sql,2,3,4,5,6,7,8,9%20FROM%20sqlite_master--`, que retorna o resultado pretendido. Neste caso, para ser bem-sucedido, o `SELECT` requer mais oito campos (`2,3,4,5,6,7,8,9`), que têm de ter valor não nulo de maneira a serem corretamente mapeados nas colunas da *query* à tabela `sqlite_master`.

Por isso, o desafio considera-se bem-sucedido.

TODO: Describe the general vulnerability class associated with each group of challenges, including relevant CWEs and typical mitigation and fixing strategies.

Tal como anteriormente, a vulnerabilidade que viabiliza este ataque é a validação inadequada do *input* do utilizador.

Em particular, as linhas de código responsáveis são as seguintes.

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

Deste modo, uma possibilidade que resolveria esta vulnerabilidade consistiria em utilizar o mecanismo de *binding* da linguagem para criar um *prepared statement* com a *query* a executar. Em concreto, o código deveria passar a ```models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%:criteria%' OR description LIKE '%:criteria%') AND deletedAt IS NULL) ORDER BY name`, { replacements: { criteria } } )```.  Assim, previne-se a possibilidade de manipulação da sintaxe da *query* através da submissão de *inputs* indevidos pelo utilizador, ao ser estabelecida previamente à entrada de qualquer *input*.

TODO: were the vulnerabilities detected by the automated (static or dynamic) analysers? why do you think that is the case?

TODO: you may patch the code and rerun the analyses. would the analysers no longer report the fixed code as vulnerabilities? why do you think that is the case?

### GDPR Data Erasure

O desafio *GDPR Data Erasure* tem como objetivo iniciar sessão com a conta do *Chris*, apesar de o utilizador ter sido eliminado. Este desafio não só está relacionado com ambos os anteriores, mas também vai para além das vulnerabilidades de *SQL Injection* ao ponto de poder ser atribuído à falta de conformidade com o Regulamento Geral de Proteção de Dados (GDPR) no processo de eliminação de dados.

A técnica utilizada anteriormente no desafio *Database Schema* pode ser repetida para pesquisar pelo e-mail e nome do utilizador *Chris*, bem como a data de eliminação da conta. Assim, envia-se o pedido HTTP `GET /rest/products/search?q=banana'))%20UNION%20SELECT%20deletedAt,username,email,1,2,3,4,5,6%20FROM%20Users--`. Deste modo, obtêm-se os campos `username`, `email` e `deletedAt` de todos os utilizadores registados na *Juice Shop*, encontrando-se facilmente o e-mail do *Chris* através de uma pesquisa: `chris.pike@juice-sh.op`.

De forma análoga ao desafio *Login Bender*, é possível iniciar sessão na conta do *Chris* utilizando o e-mail `chris.pike@juice-sh.op' --` e qualquer valor não nulo como palavra-passe.

A imagem seguinte evidencia o desafio concluído com sucesso.

![GDPR Data Erasure](/Lab3/images/GDPR-data-erasure.png)

De modo idêntico aos casos anteriores, a vulnerabilidade que possibilita a execução deste ataque é a validação incorreta do *input* do utilizador - para concretizar *SQL Injection* -, bem como a falta de cumprimento dos requisitos de conformidade do GDPR.

O código responsável por esta vulnerabilidade encontra-se nas linhas abaixo.

```js

```

TODO: which lines of which code files were responsible for the vulnerabilities?

TODO: how can the code that led to these vulnerabilities be fixed?

TODO: were the vulnerabilities detected by the automated (static or dynamic) analysers? why do you think that is the case?

TODO: you may patch the code and rerun the analyses. would the analysers no longer report the fixed code as vulnerabilities? why do you think that is the case?

## Cross-Site Scripting (XSS)

O desafio escolhido relativo a *Cross-Site Scripting* (XSS) é o ***API-Only XSS***.

### API-Only XSS

No desafio *API-Only XSS*, o pretendido é realizar um ataque de XSS persistente/armazenado com `iframe src="javascript:alert('xss')` sem utilizar o *frontend* da aplicação *web*. Assim, pretende-se que o cliente chame métodos da API não disponíveis através da interface *web*, de maneira a armazenar dados maliciosos na base de dados, capazes de afetar futuros pedidos.

O objetivo deste desafio prende-se em perceber como fazer uso da API da aplicação *web* para executar o *payload* pretendido. Ao explorar o *site* através do *browser*, monitorizando os pedidos com o *Burp Suite*, encontram-se facilmente algumas APIs, como `/Users`, `Products`, `Challenges` e `Quantitys`, entre outras. A imagem abaixo demonstra isto mesmo.

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

Ao realizar um pedido HTTP OPTIONS - no sentido de identificar todos os verbos HTTP válidos para o *endpoint* em questão, obtém-se o seguinte resultado.

![API-Only XSS](/Lab3/images/api-only-xss-3.png)

Ou seja, é possível realizar pedidos ao *endpoint* `/api/Products` utilizando os métodos HTTP GET, HEAD, PUT, PATCH, POST e DELETE.

A abordagem inicial passa por utilizar o método HTTP PUT, com o qual se verifica que um pedido a `/api/Products/id`, substituindo o campo `id` por um número arbitrário, retorna uma resposta `200 OK`, indicando sucesso.

No entanto, a tentativa de utilizar esta abordagem para alterar a descrição do produto *Orange Juice* não é bem-sucedida, visto que o conteúdo do mesmo permanece inalterado, apesar de a resposta ser `200 OK`. Isto provavelmente deve-se ao facto de um utilizador normal, isto é, não administrador, não ter permissões suficientes/necessárias para alterar um produto.

Tendo em conta que o campo `Authorization` contém um JSON *web token* - reconhecido por começar por `ey` - associado à conta do utilizador autenticado, deve ser essa a razão pela qual não é possivel alterar o conteúdo do produto. Assim, pode tentar-se descobrir o *token* da conta com permissões de administrador (`admin@juice-sh.op`), aproveitando as abordagens anteriores e o *Burp Suite*.

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

A função que contém o código vulnerável encontra-se abaixo.

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
```

## Broken Access Control

O desafio selecionado para explorar falhas de *Broken Access Control* é o ***Forged Review***.

### Forged Review

Neste desafio *Forged Review*, pretende-se publicar um comentário de *feedback*/*review* em nome de outro utilizador da plataforma. Nesse sentido, o desafio visa a demonstrar existem pedidos HTTP à REST API que não estão adequadamente protegidos e para os quais não é corretamente validada a autenticação do utilizador.

Em concreto, o utilizador-alvo - em nome do qual deve ser publicado o comentário - é o `bender@juice-sh.op`.

Tendo em conta que não é possível publicar qualquer conteúdo sem estar autenticado, opta-se por iniciar o processo por iniciar sessão com uma conta arbitrária, aproveitando a vulnerabilidade de *SQL Injection* anteriormente identificada e exemplificada. A título de exemplo, inicia-se sessão com o utilizador `stan@juice-sh.op`.

Ao utilizar o *Burp Suite* para manipular os pedidos HTTP associados à publicação de *feedback*, identifica-se o pedido HTTP em questão como sendo o seguinte, transcrito de forma simplificada.

```
PUT /rest/products/1/reviews
HTTP/1.1
{"message":"I love apples!","author":"stan@juice-sh.op"}
```

Efetivamente, o pedido HTTP contém a *review* enviada no formato JSON, com os campos `message` e `author`. O campo `message` apresenta o conteúdo a publicar, enquanto `author` contém o e-mail do utilizador associado à publicação.

Assim, ao enviar um novo pedido com estes campos modificados de maneira a enviar outra mensagem em `message` e a conter `bender@juice-sh.op` em `author`, consegue-se facilmente efetuar uma publicação em nome de outro utilizador.

De facto, este ataque explora uma vulnerabilidade de *Broken Access Control*.

O código vulnerável encontra-se abaixo.

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
        })
    }
}
```

A função `productReviews()` extrai o utilizador autenticado para a variável `user` (`const user = security.authenticatedUsers.from(req)`), mas não utiliza esse valor. Em vez disso, o `id` utilizado para a publicação do conteúdo é enviado no próprio pedido sem validação se pertence ao utilizador autenticado, em `{ _id: req.body.id }`.

Por isso, para resolver esta vulnerabilidade basta corrigir o código acima identificado, alterando-o para o seguinte, com destaque para a linha `{ _id: req.body.id, author: user.data.email }`.

```ts
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update          { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
```

Desta forma, a porção de código `author: user.data.email` vai buscar a informação do e-mail do utilizador autenticado à sessão atual, garantindo que não é submetida informação de outro utilizador, indevidamente. Assim, impede-se facilmente a adulteração de informação publica na *review*.

TODO: were the vulnerabilities detected by the automated (static or dynamic) analysers? why do you think that is the case?

TODO: you may patch the code and rerun the analyses. would the analysers no longer report the fixed code as vulnerabilities? why do you think that is the case?
