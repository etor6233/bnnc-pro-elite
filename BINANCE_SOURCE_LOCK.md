# Source lock — Binance Spot

> Observado: `2026-08-22`  
> Repositorio oficial: <https://github.com/binance/binance-spot-api-docs>  
> Revisión fijada: `976cc580553890e92031b77306147c0ed1de5a46`  
> Hash: SHA-256 de los bytes raw servidos por GitHub.

| Ruta en la revisión | Bytes | SHA-256 | Decisión condicionada |
|---|---:|---|---|
| `web-socket-streams.md` | 22958 | `32bf73a0bed3b75e3ca981fdbaf48c53544bbdfb5944ef8ed1c4d7af9aceba0a` | conexión, límites, diff-depth y reconstrucción local |
| `web-socket-api.md` | 277525 | `c09a1f5c7ebfd111fed79f07e98c3cf0d862d0f3c8d6636b57bd2dac83d09a8d` | requests WS, cuenta, comisiones y futura ejecución |
| `sbe-market-data-streams.md` | 4981 | `3e945f522c279e0dcb894b25b4933cbb5165ab488a7014356dbe496eb5b54a41` | candidate SBE: trades, best bid/ask y diff-depth 20 ms |
| `sbe/schemas/stream_1_0.xml` | 6192 | `6ea328467e144311b1f1efff38e9fe613829997f041dd02a3b7077885d10a1f7` | schema binario fijado del candidate SBE |
| `faqs/market_data_only.md` | 1616 | `57d608507426215c43f11907c07ed693f02725840d9ee4d6630f134de402b6da` | endpoints públicos sin autenticación |
| `rest-api.md` | 181189 | `49ea6809243fc7fb426e07f2fe662097736c7bb405bd2da5eef637d715427999` | snapshot, exchangeInfo, rate limits y futura order API |
| `user-data-stream.md` | 13406 | `e03f277ba7a28a4d7d0df981c4d584056c3336a37d6ce483622599723ed4b957` | balances, `executionReport`, fills y finalización del stream |
| `filters.md` | 13528 | `4b5a8f0f5d15bcf68fd7ac2059ba6c88da641c06fd7885e642330c5ac8124dd3` | filtros de símbolo/exchange y validación pre-trade |
| `errors.md` | 20321 | `5e3a9a7bda255e0177f2928bcb68ea09cf5b73a45186756d008bdf7afc3f10f9` | taxonomía de error, retry y reconcile |
| `enums.md` | 5244 | `5708fe6fdea8013f6c8a8388074c8cef8482b2b69a09181e4b2b36e0c2b4ab4b` | side, type, status, TIF, STP y estados |
| `PROD-TERMS-OF-USE.md` | 186 | `73cf92c7836939b1ef1969551fd103221f021f99628750801abcea04938d97e2` | puntero oficial a términos de producción; términos vigentes siguen siendo dinámicos |
| `faqs/api_key_types.md` | 3188 | `7b6c1727a8181fb9dc260a17a3cf666b8df3a15bd15a54cd64d525b5a6bcee1d` | tipos de API key y autenticación |
| `faqs/commission_faq.md` | 6508 | `580cfa59c9f55adae0d27bf38d2bc7f268ad759fdf054486e356464c30bbd54c` | cálculo y consulta de comisiones |
| `faqs/market_orders_faq.md` | 4681 | `8b7fd85348f84892d64a66c96332ff8d41e06b1d85c364bce963bd8a8670c167` | market orders, quantity/quote y partial expiration |
| `faqs/price_range_execution_rules.md` | 7999 | `ec6fa180dc99ea1f1846f8e310caa958c8f0ff33fec65a1b94160113f25259d7` | price-range execution y rejects/expiry aplicables |
| `faqs/stp_faq.md` | 26839 | `bcc42479c7a0eb923dbe98588848787dc1b624aaa0cba2f154bfd5649611d711` | self-trade prevention y prevented matches |
| `faqs/order_count_decrement.md` | 8910 | `d757705241bd4ef46b941f2de6184935e0b2c57e38154ef9fc9ec459f9586e83` | conteo de órdenes y rate-limit semantics |
| `faqs/order_amend_keep_priority.md` | 4705 | `b0b6fe9961e8aa71c46d76b985578c544306a764f8ab7c7d4c59322935fab8cb` | amend y conservación de prioridad |
| `faqs/sbe_faq.md` | 10963 | `41ae3db05139e03720ccaa8784ec251091af5887857946ea005b38142f708036` | alternativa SBE futura, no baseline inicial |
| `testnet/general-info.md` | 11901 | `f6ff938f0d8bb8bb6b0496ce3010aaf847c385060da49d271d34b9b8ebb60be1` | capacidades, límites, fondos virtuales y resets de Spot Testnet |
| `testnet/user-data-stream.md` | 13455 | `2075d4892c066d9fb4c0358b7546c0e27bf660e56f6f47055e1bbea93d03de32` | eventos autenticados de Spot Testnet |
| `testnet/rest-api.md` | 177083 | `a73a3d2103387e4442b91b28b12f7e59bbf2479a1ee117fdd261d2521c5625a2` | REST/order/account semantics específicas de Testnet |
| `testnet/web-socket-api.md` | 269739 | `5ee59d1a59f8b5c3410af618b235203a4e1c6959afdf735950fbaa5bc068de24` | WebSocket request API específica de Testnet |
| `testnet/web-socket-streams.md` | 22998 | `13428b2e5f4d9dc7654331d4c65e6befea776d2b7408fe5980343708f72d96e6` | market streams específicas de Testnet |
| `testnet/sbe-market-data-streams.md` | 5014 | `821da50c7e92da03bdbcda59a6207a9cf3a6fda00d871cf67521d7a83346fd2e` | SBE market data específica de Testnet |
| `testnet/enums.md` | 4821 | `85402e943809bfb05c45ca050363d246748a13f7c0a8031b50b98bbec39de54b` | enums específicos de Testnet |
| `testnet/errors.md` | 20501 | `360aeed5d5d9eda8deaf1c6e7a93369ccaf83ce70d24eecde07a1b5bf4e112b4` | errors específicos de Testnet |
| `testnet/filters.md` | 13490 | `2a2eb202df6521e954a520942157cf5c32a4e0416e551f3fd77da90d3f5fc998` | filters específicos de Testnet |
| `testnet/CHANGELOG.md` | 69389 | `929a35dd9dac6423db31803b3996dcfe1f9af1dc5cfdce6967f58e9d4af010b2` | drift específico de Testnet |
| `testnet/TESTNET-TERMS-OF-USE.md` | 221 | `69d6f58e57f0e1878ee66646ca4757e0cdfd65429ffedb6e308e7e3ab2a19b35` | términos/puntero oficial de Testnet |
| `demo-mode/general-info.md` | 8593 | `6b07adb3cc2ca92828cb74a27c7a2e3a3f7c75de9ba362843ecd1e636409073d` | diferencias Demo/Testnet/live y mantenimiento |
| `demo-mode/CHANGELOG.md` | 1776 | `b5a52f480a1831e549ab039fd7af33338052caacd3fde95fa38a19acd7ef56dc` | drift específico de Demo Mode |
| `demo-mode/DEMO-TERMS-OF-USE.md` | 212 | `ae88fa1ba16ab6c156163b4985080f1e86e9c7aaef12c92e0e1c521daa443957` | términos/puntero oficial de Demo Mode |
| `CHANGELOG.md` | 132483 | `e6da6a7bb729ec5b1aa6d3c97684bb2a1e4d3a64231b007edea42c6cceef7681` | detección de drift antes de release |

URL raw reproducible:

```text
https://raw.githubusercontent.com/binance/binance-spot-api-docs/976cc580553890e92031b77306147c0ed1de5a46/<ruta>
```

## Política de actualización

1. Consultar `refs/heads/master` y el changelog antes de comenzar una release.
2. Comparar desde esta revisión hasta el nuevo commit.
3. Clasificar cada cambio por contrato afectado: transport, codec, sequence/snapshot, filters/precision, rate, fees, account/order lifecycle o security.
4. Actualizar requisitos, fixtures y tests antes de cambiar el lock.
5. Descargar bytes por commit, registrar longitud y SHA-256 y ejecutar el gate completo aplicable.
6. No mover el lock porque “master es más nuevo”; moverlo sólo cuando la compatibilidad esté demostrada.

Una revisión fijada demuestra qué texto gobernó el build. No demuestra que Binance conserve esa versión en producción ni que un comportamiento no documentado sea estable; por eso startup y pre-release también validan compatibilidad observable y fallan cerrado ante incompatibilidades conocidas.

## Fuentes oficiales dinámicas

Estas fuentes no se congelan como sustituto del estado actual de la cuenta. Cada lectura futura debe registrar entidad/región, cuenta alias, fecha, response digest y expiración:

- portal de fees: <https://www.binance.com/en/fee/trading>;
- catálogo VIP Service: <https://developers.binance.com/en/docs/catalog/vip-and-institutional-vip-service/api/rest-api>;
- índice oficial para agentes: <https://developers.binance.com/en/docs/llms.txt>;
- cuenta: `GET /api/v3/account`, `GET /api/v3/account/commission?symbol=...` o equivalentes WebSocket;
- comisión específica de order candidate: `POST /api/v3/order/test` con `computeCommissionRates=true`;
- comisión realmente cobrada: User Data Stream/account trades.

Una tabla pública no determina por sí sola el VIP o fee efectivo de una cuenta concreta.
