export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { hash } = req.body;
  if (!hash) return res.status(400).json({ error: "Missing hash" });

  try {
    const apiKey = process.env.VT_KEY;
    if (!apiKey) return res.status(500).json({ error: "VT_KEY not set in environment variables" });

    const url = `https://www.virustotal.com/api/v3/files/${hash}`;

    const resp = await fetch(url, { headers: { "x-apikey": apiKey } });
    const data = await resp.json();

    if (!data || !data.data) {
      return res.status(404).json({ error: "No data found for this hash" });
    }

    // 精简结果
    const attributes = data.data.attributes || {};
    const last_analysis_stats = attributes.last_analysis_stats || {};
    const names = attributes.names || [];
    const signature_info = attributes.signature_info || {};
    const last_analysis_results = attributes.last_analysis_results || {};

    // 提取恶意引擎列表
    const malicious_engines = [];
    for (const [engine, result] of Object.entries(last_analysis_results)) {
      if (result.category === "malicious") malicious_engines.push(engine);
    }

    return res.status(200).json({
      hash: data.data.id,
      simplified: {
        names,
        signature_info,
        last_analysis_stats,
        malicious_engines
      },
      download_url: `/api/download/${data.data.id}`
    });

  } catch (e) {
    return res.status(500).json({ error: e.toString() });
  }
}
