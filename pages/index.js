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

    // VT 返回错误（没有 data）
    if (!data?.vt?.data) {
      setError(data?.vt?.error?.message || "VirusTotal 返回异常");
      return;
    }

    setResult(data);
  };

  // ===== 从 VT 中安全解构 =====
  const attrs = result?.vt?.data?.attributes;

  const stats = attrs?.last_analysis_stats;
  const maliciousEngines = attrs?.last_analysis_results
    ? Object.entries(attrs.last_analysis_results)
        .filter(([, v]) => v.category === "malicious")
        .map(([k]) => k)
    : [];

  const names = attrs?.names || [];
  const signature = attrs?.signature_info;

  return (
    <div style={{ padding: 20, maxWidth: 900, margin: "0 auto", fontFamily: "sans-serif" }}>
      <h1>VirusTotal Hash 查询</h1>

      <input
        value={hash}
        onChange={e => setHash(e.target.value)}
        placeholder="输入文件 hash"
        style={{ width: "100%", padding: 8, fontSize: 16 }}
      />
      <button onClick={submit} style={{ marginTop: 10, padding: "8px 16px" }}>
        查询
      </button>

      {/* 错误显示 */}
      {error && (
        <div style={{ marginTop: 20, color: "red" }}>
          ❌ {error}
        </div>
      )}

      {/* 查询结果 */}
      {attrs && (
        <div style={{ marginTop: 30 }}>
          <h2>检测结果</h2>

          <p>
            检测率：
            <b>
              {stats.malicious} /{" "}
              {Object.values(stats).reduce((a, b) => a + b, 0)}
            </b>
          </p>

          <h3>恶意引擎</h3>
          {maliciousEngines.length === 0 ? (
            <p>无</p>
          ) : (
            <ul>
              {maliciousEngines.map(e => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}

          <h3>文件名</h3>
          <ul>
            {names.slice(0, 10).map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>

          {signature && (
            <>
              <h3>签名信息</h3>
              <pre style={{ background: "#222", color: "#fff", padding: 10 }}>
                {JSON.stringify(signature, null, 2)}
              </pre>
            </>
          )}

          <a
            href={`/api/download/${result.vt.data.id}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            下载文件（如果权限允许）
          </a>
        </div>
      )}
    </div>
  );
}
