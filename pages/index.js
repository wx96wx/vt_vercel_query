import { useState } from "react";

export default function Home() {
  const [hash, setHash] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!hash) return;
    setLoading(true);
    setError(null);
    setData(null);

    try {
      const resp = await fetch("/api/vt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash })
      });

      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || "查询失败");

      setData(json.vt);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  if (data?.error) {
    return <pre>{JSON.stringify(data, null, 2)}</pre>;
  }

  const attr = data?.data?.attributes;

  // 检测率
  const stats = attr?.last_analysis_stats;
  const detectionRate =
    stats ? `${stats.malicious}/${stats.malicious + stats.undetected}` : "N/A";

  // 命中的恶意引擎
  const engines =
    attr?.last_analysis_results
      ? Object.entries(attr.last_analysis_results)
          .filter(([_, v]) => v.category === "malicious")
          .map(([k]) => k)
      : [];

  // 文件名
  const names = attr?.names || [];

  // 签名信息
  const sig = attr?.signature_info;
  const x509 = sig?.x509?.[0];

  return (
    <div style={{ padding: 24, fontFamily: "sans-serif", maxWidth: 1100, margin: "0 auto" }}>
      <h1>VirusTotal 文件查询</h1>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <input
          value={hash}
          onChange={e => setHash(e.target.value)}
          placeholder="输入文件 hash（MD5 / SHA1 / SHA256）"
          style={{
            flex: "1 1 400px",
            padding: 10,
            fontSize: 16
          }}
        />
        <button
          onClick={submit}
          disabled={loading}
          style={{ padding: "10px 18px", fontSize: 16 }}
        >
          {loading ? "查询中…" : "查询"}
        </button>
      </div>

      {error && (
        <div style={{ marginTop: 20, color: "red" }}>
          错误：{error}
        </div>
      )}

      {attr && (
        <div style={{ marginTop: 30 }}>
          <h2>检测概览</h2>
          <ul>
            <li><b>检测率：</b>{detectionRate}</li>
            <li>
              <b>恶意引擎：</b>
              {engines.length ? engines.join(", ") : "无"}
            </li>
          </ul>

          <h2>文件名（历史出现过）</h2>
          <ul style={{ maxHeight: 200, overflowY: "auto" }}>
            {names.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>

          {sig && (
            <>
              <h2>数字签名信息</h2>
              <ul>
                <li><b>产品：</b>{sig.product}</li>
                <li><b>验证状态：</b>{sig.verified}</li>
                <li><b>文件版本：</b>{sig["file version"]}</li>
                <li><b>原始文件名：</b>{sig["original name"]}</li>
              </ul>

              {x509 && (
                <>
                  <h3>X509 证书</h3>
                  <ul>
                    <li><b>签名用途：</b>{x509["valid usage"]}</li>
                    <li><b>证书主体：</b>{x509.name}</li>
                    <li><b>颁发者：</b>{x509["cert issuer"]}</li>
                    <li><b>算法：</b>{x509.algorithm}</li>
                    <li><b>有效期：</b>{x509["valid from"]} → {x509["valid to"]}</li>
                    <li><b>SHA256 指纹：</b>{x509.thumbprint_sha256}</li>
                  </ul>
                </>
              )}
            </>
          )}

          <div style={{ marginTop: 20 }}>
            <a
              href={`/api/download/${data.data.id}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              下载文件（如果 API 权限允许）
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
