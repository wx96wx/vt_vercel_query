import { useState } from "react";

export default function Home() {
  const [hash, setHash] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const submit = async () => {
    setError(null);
    setData(null);

    const resp = await fetch("/api/vt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash })
    });

    const json = await resp.json();
    if (!resp.ok) {
      setError(json.error || "查询失败");
      return;
    }

    setData(json.vt.data.attributes);
  };

  return (
    <div style={{ padding: 24, maxWidth: 1000, margin: "0 auto", fontFamily: "sans-serif" }}>
      <h1>VirusTotal 文件查询</h1>

      <input
        value={hash}
        onChange={e => setHash(e.target.value)}
        placeholder="输入 SHA256 / MD5 / SHA1"
        style={{ width: "70%", padding: 8, fontSize: 16 }}
      />
      <button onClick={submit} style={{ marginLeft: 10, padding: "8px 16px" }}>
        查询
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {data && (
        <>
          {/* 检测率 */}
          <h2>检测结果</h2>
          <p>
            恶意：
            <b style={{ color: "red" }}>{data.last_analysis_stats.malicious}</b>
            {" / "}
            {Object.values(data.last_analysis_stats).reduce((a, b) => a + b, 0)}
          </p>

          {/* 恶意引擎 */}
          <h3>恶意引擎</h3>
          <ul>
            {Object.entries(data.last_analysis_results)
              .filter(([_, v]) => v.category === "malicious")
              .map(([engine, v]) => (
                <li key={engine}>
                  {engine} — {v.result}
                </li>
              ))}
          </ul>

          {/* 文件名 */}
          <h3>关联文件名</h3>
          <ul>
            {data.names?.slice(0, 10).map((name, i) => (
              <li key={i}>{name}</li>
            ))}
          </ul>

          {/* 签名信息 */}
          {data.signature_info && (
            <>
              <h3>数字签名</h3>
              <p><b>签名方：</b>{data.signature_info.signers}</p>

              {data.signature_info.signers_details?.map((s, i) => (
                <div key={i} style={{ border: "1px solid #ccc", padding: 10, marginBottom: 10 }}>
                  <div>名称：{s.name}</div>
                  <div>算法：{s.algorithm}</div>
                  <div>有效期：{s["valid from"]} → {s["valid to"]}</div>
                  <div>颁发者：{s["cert issuer"]}</div>
                </div>
              ))}
            </>
          )}

          {/* 下载 */}
          <a
            href={`/api/download/${data.sha256}`}
            target="_blank"
            rel="noreferrer"
            style={{ display: "inline-block", marginTop: 20 }}
          >
            下载文件（如 API 权限允许）
          </a>
        </>
      )}
    </div>
  );
}
