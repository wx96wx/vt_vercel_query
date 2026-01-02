export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const { hash } = req.body;
  if (!hash) return res.status(400).json({ error: "Missing hash" });

  const apiKey = process.env.VT_KEY;
  if (!apiKey) return res.status(500).json({ error: "VT_KEY not set" });

  const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { "x-apikey": apiKey }
  });

  const data = await r.json();
  const a = data.data?.attributes;
  if (!a) return res.status(404).json({ error: "File not found" });

  const stats = a.last_analysis_stats;
  const engines = Object.entries(a.last_analysis_results || {})
    .filter(([, v]) => v.category === "malicious")
    .map(([k]) => k);

  res.json({
    filename: a.meaningful_name,
    signature: a.signature_info?.product || "",
    malicious: stats.malicious,
    total: Object.values(stats).reduce((a, b) => a + b, 0),
    engines
  });
}
