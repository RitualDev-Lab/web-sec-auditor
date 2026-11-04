# 🚀 Product Hunt & Hacker News Pre-Launch Audit Sales Playbook

---

## 🎯 Target Audience (Makers Launching in the Next 24–72 Hours)
Founders and solo developers preparing to launch on **Product Hunt**, **Hacker News (Show HN)**, or **Twitter/X**:
- They have worked for 3–6 months on their app.
- They are anxious and terrified that on launch day:
  1. A security researcher breaks their agent with prompt injection.
  2. Someone scrapes their API and runs up a $2,000 OpenAI bill.
  3. Leaked credentials or CORS bugs get exposed publicly in the comments.
- **$199** is an immediate no-brainer insurance policy for peace of mind.

---

## 📍 Where to Find 20 Targets in 10 Minutes

1. **Product Hunt "Coming Soon"**:
   - Go to: https://www.producthunt.com/coming-soon
   - Filter or look for products tagged: **Artificial Intelligence**, **Developer Tools**, **Productivity**.
   - Click on the Maker profile &rarr; grab their Twitter / X or LinkedIn handle.

2. **Twitter / X Advanced Search**:
   - Query: `("launching on product hunt" OR "launching tomorrow" OR "launching this week") AND (AI OR agent OR tool)`
   - You will see 15–30 makers tweeting about their launch scheduled for tomorrow or this Thursday.

3. **Hacker News "Show HN" / "Newest"**:
   - https://news.ycombinator.com/show
   - https://news.ycombinator.com/newest
   - Scan for projects where developers post early demos.

---

## 💥 Strategy A: The "Free Teaser" Method (Highest Conversion Rate ~40%)

Before sending a cold message, spend **30 seconds** running a DAST check on their public landing page or API:

```bash
cd D:\Git_Projects\web-sec-auditor
pnpm run scan-url https://their-app.com
```

Pick **1 real, non-destructive finding** (e.g. Missing `Content-Security-Policy`, Permissive CORS wildcard `*`, or missing `X-Frame-Options` allowing iframe clickjacking).

### The DM Template:
> **Hey [Maker Name]!**  
> 
> Saw you’re launching **[Product Name]** on Product Hunt this week — UI looks super clean!  
> 
> I ran a quick routine scan on your domain and noticed a small header misconfiguration: your server is returning `Access-Control-Allow-Origin: *` without rate limiting, which could let third-party scripts scrape your endpoints once launch traffic surges.  
> 
> (Here's the quick fix: add `helmet.contentSecurityPolicy()` in your server middleware).  
> 
> We run automated **2-hour pre-launch penetration audits** for AI tools with AgentShield (testing prompt injections, secret leaks in client bundles, and tool escapes). For **$199**, we give you a full interactive report, code patches, and an **"AgentShield Verified Secure"** badge to embed on your launch page and maker comment.  
> 
> Here’s the audit breakdown & sample report: https://ritualdev.in/audit  
> 
> Rooting for your launch! Let me know if you want us to run a full sweep today.

---

## ⚡ Strategy B: Direct Pre-Launch Insurance Pitch (Fast Volume)

Send this directly to 15 makers on Twitter or LinkedIn:

> **Hey [Maker Name]!**  
> 
> Huge congrats on prepping the launch for **[Product Name]**!  
> 
> Quick question: are you guys running any pre-launch security or prompt injection checks before the Hacker News / Product Hunt crowd hits your app?  
> 
> We run **2-hour pre-launch penetration audits** for AI tools & MCP servers using AgentShield. For **$199**, we test for leaked OpenAI/Stripe tokens, AST shell escapes, and CORS traps, and deliver an interactive executive dashboard + the **Verified Secure (2026)** embed badge to build trust with early adopters.  
> 
> You can check out the packages & book here: https://ritualdev.in/audit  
> 
> Good luck with the launch! 🚀

---

## 🛠️ Step-by-Step Delivery When an Order Comes In (Takes 5 Minutes)

When an order arrives in `D:\Git_Projects\ritualdev-web\data\audit-orders.json` or via Dodo Payments notification:

1. Open your terminal:
   ```bash
   cd D:\Git_Projects\web-sec-auditor
   pnpm run audit:client --target https://client-app.com --name "Client Product" --email "founder@client.com"
   ```
2. The script finishes in ~10 seconds and creates:
   `D:\Git_Projects\web-sec-auditor\audit-deliveries\client-product/`
   - `executive-audit-report.html`
   - `results.sarif`
   - `verified-badge.svg`
   - `delivery-email.md`
3. Open `delivery-email.md`, attach the HTML report, and send it to the client!
4. You just earned **$199** for 5 minutes of automated execution.
