# Lab 1 - Low-Level Security

Os programas escolhidos para investigar foram o `misused_string_fct_taint` (145/146) e o `os_cmd_scope` (155/156), disponibilizados na pasta `Lab1`.

## 145/146 - `misused_string_fct_taint`

O ficheiro `misused_string_fct_taint-bad.c` contém o código abaixo.

```c
#define MAX_SIZE 10

int main(int argc, char *argv[])
{
	char str[MAX_SIZE];
	// Often Misused String Management:
	// Buffer overflow with strcpy function
	if (argc > 1)
		strcpy(str, argv[1]);							/* FLAW */
	return 0;
}
```

Este código contém uma vulnerabilidade de *buffer overflow*, visto que o *input* do utilizador fornecido como primeiro argumento do programa (`argv[1]`) é copiado pela função `strcpy()` para o *array* `str` de tamanho fixo 10, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, ou seja, permitindo que os limites da memória alocada para o *array* sejam ultrapassados. Como tal, um atacante pode inserir um *input* com comprimento superior ou igual a 10 *bytes* de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução.

![Exemplos de Execução](/Lab1/images/145-example.png)

Assim sendo, existem três CWEs associadas a esta vulnerabilidade:

1. **[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119):** a ausência de verificação do comprimento do *input* em relação ao tamanho do *buffer* permite operações de escrita fora dos limites definidos para o mesmo, tal como demonstra a imagem abaixo.
2. **[CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120):** o *input* é copiado para o *buffer* sem se verificar se o tamanho do *input* é menor do que o tamanho do *buffer*, possibilitando um *buffer overflow*.
3. **[CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121):** o *buffer* alvo de *overflow* está alocado na *stack*, visto que é uma variável local da função.

![CWE 119](/Lab1/images/145-cwe.png)

Tendo em conta que o código do programa está escrito em C/C++, é adequado correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/145-flawfinder.png)

Ora, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *buffer overflow* em causa no código exposto, indicando duas das CWEs associadas (CWE-119 e CWE-120), tal como esperado.

Além disso, o ***Snyk Code Checker*** também identifica corretamente a falha no código.

![Snyk Code Checker](/Lab1/images/145-snyk.png)

No entanto, a CWE associada é erradamente identificada como sendo a **[CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122)**, o que não corresponde à realidade, dado que o *buffer* afetado é alocado na *stack* - por ser uma variável local - e não na *heap* - por não existir qualquer chamada à função `malloc()`.

Foi também testado o ***SemGrep***, mas este *scanner* não detetou qualquer vulnerabilidade no programa usando apenas as regras predefinidas.

TODO: *From the error log (or lack thereof), what can you deduct about the scanner's analysis technique?*

...

TODO: The tools used to analyze misused_string_fct_taint-bad.c were Valgrind, due to it's usefulness in detecting stack smashing and stack overflow based vulnerabilities. When using Valgrind to analyze this program, intially we tried using an input bellow 10, the program didn't identify any issues. We then decided to use the same command but with an input of more than 10. Valgrind was able to identify that there was stack smashing happening.

## 155/156 - `os_cmd_scope`

O ficheiro `os_cmd_scope-bad.c` contém o código abaixo.

```c
#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";

void runCommand(char *str) 
{
	if(system(str) < 0)							        /* FLAW */
		fprintf(stderr, "system() failed");
}

int main(int argc, char *argv[])
{
	char sys[512];
	char buff[512];
	if (fgets(buff,512 - SIZE_CMD,stdin))
	{
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

Este código contém uma vulnerabilidade de *command injection*, visto que o *input* do utilizador obtido do *standard input* (`stdin`) para o *array* `buff` é concatenado pela função `strcat()` no *array* `sys`, que contém previamente o valor da variável `cmd`, ou seja, o comando `/usr/bin/cat`, que será executado pelo sistema através da chamada à função `system()`. Como tal, um atacante pode inserir um *input* malicioso que, após a execução do comando `/usr/bin/cat ...`, execute outro comando arbitrário, realizando um ataque de *command injection*.

Efetivamente, as execuções seguintes demonstram a execução de diferentes comandos fornecidos como *input* ao programa, contornando o seu propósito de executar unicamente `cat` e concretizando, assim, um ataque de *command injection*.

![Exemplos de Execução](/Lab1/images/155-example.png)

Assim sendo, existe uma principal CWE associada a esta vulnerabilidade:

1. **[CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78):** o programa constrói parte de um comando do sistema operativo utilizando *input* externo fornecido pelo utilizador, mas sem neutralizar os elementos que podem modificar o comportamento esperado do comando a executar, tal como demonstra a imagem abaixo.

![CWE 78](/Lab1/images/155-cwe.png)

Note-se que, dadas as chamadas às funções `strcpy()` e `strcat()` sem a devida validação do tamanho do *input*, podem ainda ser concretizados ataques de *buffer overflow*, tal como explicado anteriormente, estando estes casos igualmente associados às CWEs anteriores, pelo que estas não serão novamente exploradas.

Como o código do programa está também escrito em C/C++, pode correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/155-flawfinder.png)

De facto, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *command injection* em causa no código exposto, identificando a CWE associada (CWE-78), tal como seria expectável. A par disso, esta ferramenta alerta ainda para as restantes CWEs já abordadas (CWE-119 e CWE-120) relacionadas com os possível ataques de *buffer overflow*.

De forma análoga à anterior, testou-se também o ***Snyk Code Checker*** para este caso.

![Snyk Code Checker](/Lab1/images/155-snyk.png)

Ora, o ***Snyk Code Checker*** também identifica corretamente a falha no código e a CWE associada.

Finalmente, foi igualmente executado o ***SemGrep***.

![SemGrep](/Lab1/images/155-semgrep-1.png)

![SemGrep](/Lab1/images/155-semgrep-2.png)

Para além de realçar a vulnerabilidade de *command injection* devido à ausência de neutralização do *input*, o ***SemGrep*** alerta para a chamada à função `system()`, que deve ser evitada precisamente por permitir a execução de múltiplos comandos de forma eventualmente indevida. Assim sendo, a ferramenta sugere a utilização de outras interfaces mais restritivas, como `execve()`. Em ambas as situações, a CWE-78 é corretamente identificada.
