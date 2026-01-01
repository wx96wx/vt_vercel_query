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

    if (data.error) {
      setError(data.error);
    } else {
      setResult(data);
    }
  };

  const attr = result?.vt?.data?.attributes;

  return (
    <div style={{ padding: 20, maxWidth: 900, margin: "0 auto", fontFamily: "sans-serif" }}>
      <h1>VirusTotal 文件查询</h1>

      <div style={{ display: "flex", gap: 10 }}>
        <input
          value={hash}
          onChange={e => setHash(e.target.value)}
          placeholder="输入文件 hash (MD5 / SHA1 / SHA256)"
          style={{ flex: 1, padding: 8, fontSize: 16 }}
        />
        <button onClick={submit} style={{ padding: "8px 16px" }}>
          查询
        </button>
      </div>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {attr && (
        <div style={{ marginTop: 20 }}>
          {/* 检测率 */}
          <h3>检测结果</h3>
          <p>
            恶意：
            <b style={{ color: "red" }}>
              {attr.last_analysis_stats.malicious}
            </b>{" "}
            / 总数：
            {Object.values(attr.last_analysis_stats).reduce((a, b) => a + b, 0)}
          </p>

          {/* 恶意引擎 */}
          <h3>恶意引擎</h3>
          <ul>
            {Object.entries(attr.last_analysis_results)
              .filter(([, v]) => v.category === "malicious")
              .map(([engine, v]) => (
                <li key={engine}>
                  {engine}: {v.result}
                </li>
              ))}
          </ul>

          {/* 文件名 */}
          <h3>关联文件名</h3>
          <ul>
            {attr.names?.slice(0, 10).map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>

          {/* 签名信息 */}
          {attr.signature_info && (
            <>
              <h3>签名信息</h3>
              <pre style={{ background: "#222", color: "#fff", padding: 10 }}>
                {JSON.stringify(attr.signature_info, null, 2)}
              </pre>
            </>
          )}

          {/* 下载 */}
          <a
            href={`/api/download/${result.vt.data.id}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            下载文件（若 API 权限允许）
          </a>
        </div>
      )}
    </div>
  );
}
