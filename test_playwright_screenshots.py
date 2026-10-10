import asyncio
import os
from playwright.async_api import async_playwright

ARTIFACT_DIR = r"C:\Users\saive\.gemini\antigravity-ide\brain\0c578552-a113-4a71-bceb-457fe25144e9"

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        page.set_viewport_size({"width": 1280, "height": 800})
        
        print("Navigating to dashboard...")
        await page.goto("http://localhost:8000")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "1_dashboard.png"))
        
        print("Navigating to upload page...")
        await page.locator("#nav-upload").click()
        await page.wait_for_timeout(1000)
        
        print("Uploading pcap file...")
        file_path = r"c:\Users\saive\OneDrive\Desktop\Mini_Project\data\demo_capture.pcap"
        await page.locator("#fileInput").set_input_files(file_path)
        await page.wait_for_timeout(500)
        
        print("Analyzing...")
        await page.locator("#analyzeBtn").click()
        
        # Wait for results to load (wait for the page-result section to be active and loading overlay to hide)
        print("Waiting for analysis results...")
        await page.wait_for_selector("#page-result.active", timeout=60000)
        await page.wait_for_selector("#loadingOverlay", state="hidden", timeout=60000)
        await page.wait_for_timeout(2000)
        
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "2_analysis_result.png"), full_page=True)
        
        print("Blocking IP...")
        # Try to click a Block button
        block_buttons = await page.get_by_role("button", name="Block").all()
        if block_buttons:
            await block_buttons[0].click()
            await page.wait_for_timeout(1000)
        
        print("Navigating to Blocked IPs page...")
        await page.locator("#nav-blocked").click()
        await page.wait_for_timeout(1000)
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "3_blocked_ips.png"))
        
        await browser.close()
        print("Done capturing screenshots.")

if __name__ == "__main__":
    asyncio.run(run())
