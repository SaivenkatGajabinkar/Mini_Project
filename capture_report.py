import asyncio
import os
from playwright.async_api import async_playwright

ARTIFACT_DIR = r"C:\Users\saive\.gemini\antigravity-ide\brain\0c578552-a113-4a71-bceb-457fe25144e9"

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.set_viewport_size({"width": 1280, "height": 800})
        
        print("Navigating to history...")
        await page.goto("http://localhost:8000")
        await page.wait_for_timeout(2000)
        
        await page.locator("#nav-history").click()
        await page.wait_for_timeout(1000)
        
        print("Clicking first capture...")
        await page.locator("#historyBody tr").first.click()
        
        await page.wait_for_selector("#page-result.active", timeout=10000)
        await page.wait_for_timeout(2000)
        
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "4_analysis_fixed.png"), full_page=True)
        
        print("Clicking Download Report...")
        async with context.expect_page() as new_page_info:
            await page.locator("#downloadReportBtn").click()
        report_page = await new_page_info.value
        
        await report_page.wait_for_load_state()
        await report_page.wait_for_timeout(2000)
        
        print("Taking report screenshot...")
        await report_page.screenshot(path=os.path.join(ARTIFACT_DIR, "5_report.png"), full_page=True)
        
        await browser.close()
        print("Done capturing screenshots.")

if __name__ == "__main__":
    asyncio.run(run())
