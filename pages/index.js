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
      <h1>VirusTotal Hash 查询</h1>

      <input
        value={hash}
        onChange={e => setHash(e.target.value)}
        placeholder="输入文件 hash"
        style={{ width: "100%", padding: 8 }}
      />

      <button onClick={submit} style={{ marginTop: 10 }}>
        查询
      </button>

      {result && !result.error && (
        <div style={{ marginTop: 20 }}>
          <p><b>文件名：</b>{result.filename || "-"}</p>
          <p><b>签名：</b>{result.signature || "-"}</p>
          <p><b>检测率：</b>{result.malicious}/{result.total}</p>

          <p><b>恶意引擎：</b></p>
          <ul>
            {result.engines.map(e => <li key={e}>{e}</li>)}
          </ul>

          <a href={`/api/download/${hash}`} target="_blank">
            下载文件（如 API 权限允许）
          </a>
        </div>
      )}

      {result?.error && <p style={{ color: "red" }}>{result.error}</p>}
    </div>
  );
}
