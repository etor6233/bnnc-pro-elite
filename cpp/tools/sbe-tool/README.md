# tools/sbe-tool — official SBE code generator (pinned)

- Jar: `uk.co.real-logic:sbe-all:1.35.1` from Maven Central.
  SHA256 `456384ED1DB090D018B4DC15BE152D371FA192E96AA4C98D362CC163BD18777E`.
  (Latest published at capture time; the captured reference repo is
  1.41.0-SNAPSHOT — SBE wire format is version-stable for schema version 0.)
- `gen/spot_stream/*.h`: generated with
  `java -Dsbe.output.dir=gen -Dsbe.target.language=Cpp -jar sbe-all-1.35.1.jar ../../sbe/schema/stream_1_0.xml`
  from the pinned Binance schema. Apache-2.0 (tool output).
- The jar itself is NOT committed; CI does not need it (golden vectors are
  regenerated with the committed generated encoder). To re-derive the headers
  from scratch, download the pinned jar and re-run the command above.
