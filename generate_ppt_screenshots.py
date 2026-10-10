import asyncio
import os
from playwright.async_api import async_playwright

ARTIFACT_DIR = r"C:\Users\saive\.gemini\antigravity-ide\brain\b7f0da28-b3ae-41aa-9b9d-4d462cecfff4"

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        page.set_viewport_size({"width": 1280, "height": 800})
        
        print("Navigating to dashboard...")
        await page.goto("http://localhost:8000")
        await page.wait_for_timeout(2000)
        
        print("Uploading pcap file...")
        await page.locator("#nav-upload").click()
        await page.wait_for_timeout(1000)
        
        file_path = r"c:\Users\saive\OneDrive\Desktop\Mini_Project\data\danger_attack.pcap"
        await page.locator("#fileInput").set_input_files(file_path)
        await page.wait_for_timeout(500)
        
        # Screenshot 1: Upload screen with file selected
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "ppt_1_upload.png"))
        
        print("Analyzing...")
        await page.locator("#analyzeBtn").click()
        
        print("Waiting for analysis results...")
        await page.wait_for_selector("#page-result.active", timeout=60000)
        await page.wait_for_selector("#loadingOverlay", state="hidden", timeout=60000)
        await page.wait_for_timeout(2000)
        
        # Screenshot 2: Attack detected screen (results)
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "ppt_2_attack_detected.png"), full_page=True)
        
        print("Blocking IP...")
        block_buttons = await page.get_by_role("button", name="Block").all()
        if block_buttons:
            await block_buttons[0].click()
            await page.wait_for_timeout(1000)
        
        print("Navigating to Blocked IPs page...")
        await page.locator("#nav-blocked").click()
        await page.wait_for_timeout(1000)
        
        # Screenshot 3: Blocked IPs screen
        await page.screenshot(path=os.path.join(ARTIFACT_DIR, "ppt_3_blocked_ips.png"))
        
        await browser.close()
        print("Done capturing screenshots for PPT.")

if __name__ == "__main__":
    asyncio.run(run())
