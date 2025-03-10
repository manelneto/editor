# Lab 1 - Low-Level Security

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

Este código contém uma vulnerabilidade de *buffer overflow*, visto que o *input* do utilizador fornecido como primeiro argumento do programa (`argv[1]`) é copiado pela função `strcpy` para o *array* `str` de tamanho fixo 10, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, ou seja, permitindo que os limites da memória alocada para o *array* sejam ultrapassados. Como tal, um atacante pode inserir um *input* com comprimento superior ou igual a 10 *bytes* de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução.

![Exemplos de Execução](/Lab1/images/145-example.png)

Assim sendo, existem três CWEs associadas com esta vulnerabilidade:

1. **[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119):** a ausência de verificação do comprimento do *input* em relação ao tamanho do *buffer* permite operações de escrita fora dos limites definidos para o mesmo.
2. **[CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120):** o *input* é copiado para o *buffer* sem se verificar se o tamanho do *input* é menor do que o tamanho do *buffer*, possibilitando um *buffer overflow*.
3. **[CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121):** o *buffer* alvo de *overflow* está alocado na *stack*, visto que é uma variável local da função.

![CWE 119](/Lab1/images/145-cwes.png)

Tendo em conta que o código do programa está escrito em C/C++, é adequado correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/145-flawfinder.png)

Ora, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *buffer overflow* em causa no código exposto, indicando duas das CWEs associadas (CWE-119 e CWE-120), tal como esperado.

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
