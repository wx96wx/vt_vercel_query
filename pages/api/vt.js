export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { hash } = req.body;
  if (!hash) {
    return res.status(400).json({ error: "Missing hash" });
  }

  try {
    const apiKey = process.env.VT_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: "VT_KEY not set" });
    }

    const resp = await fetch(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      {
        headers: { "x-apikey": apiKey }
      }
    );

    const json = await resp.json();
    const attr = json?.data?.attributes;

    if (!attr) {
      return res.status(404).json({ error: "File not found on VirusTotal" });
    }

    /* 1️⃣ 检测率 */
    const stats = attr.last_analysis_stats;
    const total =
      stats.harmless +
      stats.malicious +
      stats.suspicious +
      stats.undetected;

    const detection_ratio = `${stats.malicious}/${total}`;

    /* 2️⃣ 恶意引擎 */
    const malicious_engines = Object.entries(
      attr.last_analysis_results || {}
    )
      .filter(([, v]) => v.category === "malicious")
      .map(([engine, v]) => ({
        engine,
        result: v.result
      }));


    /* 3️⃣ 文件名 */
    const names = attr.names || [];

    /* 4️⃣ 签名信息 */
    const signature_info = attr.signature_info || null;

    return res.status(200).json({
      hash,
      detection_ratio,
      malicious_engines,
      names,
      signature_info,
      download: `/api/download/${hash}`
    });
  } catch (e) {
    res.status(500).json({ error: e.toString() });
  }
}
