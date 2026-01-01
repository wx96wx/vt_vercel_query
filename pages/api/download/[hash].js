export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).end();
  }

  const { hash } = req.query;
  const apiKey = process.env.VT_KEY;

  if (!apiKey) {
    return res.status(500).send("VT_KEY not set");
  }

  const vtResp = await fetch(
    `https://www.virustotal.com/api/v3/files/${hash}/download`,
    { headers: { "x-apikey": apiKey } }
  );

  if (!vtResp.ok) {
    const t = await vtResp.text();
    return res.status(vtResp.status).send(t);
  }

  res.setHeader("Content-Disposition", `attachment; filename="${hash}"`);
  vtResp.body.pipe(res);
}
