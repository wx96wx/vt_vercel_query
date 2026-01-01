import { useState } from "react";

export default function Home() {
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const submit = async () => {
    setError(null);
    setResult(null);

    const resp = await fetch("/api/vt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash })
    });

    const data = await resp.json();
    if (!resp.ok) {
      setError(data.error || "查询失败");
      return;
    }
    setResult(data);
  };

  return (
    <div style={{ padding: 20, maxWidth: 900, margin: "0 auto", fontFamily: "sans-serif" }}>
      <h1>VirusTotal Hash 查询</h1>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <input
          value={hash}
          onChange={e => setHash(e.target.value)}
          placeholder="输入文件 hash (MD5 / SHA1 / SHA256)"
          style={{ flex: "1 1 400px", padding: 8, fontSize: 16 }}
        />
        <button onClick={submit} style={{ padding: "8px 16px", fontSize: 16 }}>
          查询
        </button>
      </div>

      {error && <p style={{ color: "red", marginTop: 20 }}>{error}</p>}

      {result && (
        <div style={{ marginTop: 30 }}>
          <h3>查询结果</h3>

          <ul>
            <li><b>文件名：</b>{result.filename || "未知"}</li>
            <li><b>检测率：</b>{result.malicious}/{result.total}</li>
            <li><b>签名 / 类型：</b>{result.signature || "无"}</li>
          </ul>

          {result.engines.length > 0 && (
            <>
              <h4>恶意引擎</h4>
              <ul>
                {result.engines.map(e => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </>
          )}

          <a
            href={`/api/download/${result.hash}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ display: "inline-block", marginTop: 10 }}
          >
            下载文件（若 API 权限允许）
          </a>
        </div>
      )}
    </div>
  );
}
