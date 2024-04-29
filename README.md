# Miniscript compiler

## Installation

```bash
cargo install miniscript-compiler
```

## Usage

```bash
miniscript-compiler descriptor "eltr(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e, { 
    and_v(
        and_v(
            spk_eq(out_spk(0), 5120d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e), 
            value_eq(out_value(0), 010000000000000000)             
        ),             
        and_v(            
            spk_eq(out_spk(1), 5120d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),
            value_eq(out_value(1), 010000000000000000)             
        )
    ), 
    and_v(             
        v:pk(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e), 
        older(1024)         
    )     
})"
```
