import { useState } from "react";

export default function Home() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);

  const submit = async () => {
    const resp = await fetch("/api/vt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash })
    });
    setResult(await resp.json());
  };

  return (
    <div style={{ padding: 20, maxWidth: 800, margin: "0 auto" }}>
      <h1>VirusTotal Hash query</h1>

      <input
        value={hash}
        onChange={e => setHash(e.target.value)}
        placeholder="input file hash"
        style={{ width: "100%", padding: 8 }}
      />

      <button onClick={submit} style={{ marginTop: 10 }}>
        查询
      </button>

      {result && !result.error && (
        <div style={{ marginTop: 20 }}>
          <p><b>filename：</b>{result.filename || "-"}</p>
          <p><b>signature：</b>{result.signature || "-"}</p>
          <p><b>malicious：</b>{result.malicious}/{result.total}</p>

          <p><b>engines：</b></p>
          <ul>
            {result.engines.map(e => <li key={e}>{e}</li>)}
          </ul>

          <a href={`/api/download/${hash}`} target="_blank">
            download
          </a>
        </div>
      )}

      {result?.error && <p style={{ color: "red" }}>{result.error}</p>}
    </div>
  );
}
