export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { hash } = req.body;
  if (!hash) {
    return res.status(400).json({ error: "Missing hash" });
  }

  const apiKey = process.env.VT_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "VT_KEY not set" });
  }

  const resp = await fetch(
    `https://www.virustotal.com/api/v3/files/${hash}`,
    { headers: { "x-apikey": apiKey } }
  );

  if (!resp.ok) {
    const t = await resp.text();
    return res.status(resp.status).json({ error: t });
  }

  const data = await resp.json();
  const attr = data.data.attributes;

  // 统计恶意引擎
  const stats = attr.last_analysis_stats;
  const engines = Object.entries(attr.last_analysis_results)
    .filter(([, v]) => v.category === "malicious")
    .map(([k]) => k);

  res.json({
    hash,
    filename: attr.meaningful_name || attr.names?.[0],
    malicious: stats.malicious,
    total: Object.values(stats).reduce((a, b) => a + b, 0),
    engines,
    signature: attr.signature_info?.description || attr.type_tag || null
  });
}
