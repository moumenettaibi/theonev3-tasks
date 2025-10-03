import asyncio
from playwright.async_api import async_playwright, expect
import time

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            # Generate a unique username for this test run
            timestamp = int(time.time())
            username = f"testuser{timestamp}"
            password = "password123"

            # 1. Sign up a new user
            await page.goto("http://localhost:5002/signup")
            await page.get_by_label("Username").fill(username)
            await page.get_by_label("Password").fill(password)
            await page.get_by_role("button", name="Create Account").click()

            # Wait for navigation to the main app page (tasks page)
            await expect(page).to_have_url("http://localhost:5002/~", timeout=10000)
            print("Signup and login successful.")

            # 2. Navigate to the new Notes page via the dropdown
            await page.locator(".logo").click()
            await page.get_by_role("link", name="Yajora Notes").click()
            await expect(page).to_have_url("http://localhost:5002/notes")
            await expect(page.get_by_role("heading", name="Notes")).to_be_visible()
            print("Navigated to Notes page.")

            # 3. Create a new note
            await page.locator("#addNoteBtn").click()
            await expect(page.get_by_placeholder("Note Title")).to_be_visible()

            note_title = "My First Markdown Note"
            note_content = """# Heading 1
**This is bold text.**
*This is italic.*
- List item 1
- List item 2
```python
print("Hello, World!")
```"""
            await page.get_by_placeholder("Note Title").fill(note_title)
            await page.get_by_placeholder("Start writing your note... (Markdown is supported)").fill(note_content)
            await page.get_by_role("button", name="Save").click()
            print("Note created.")

            # 4. Reload the page to ensure persistence
            await page.reload()
            await expect(page.get_by_role("heading", name="Notes")).to_be_visible(timeout=10000)
            print("Page reloaded.")

            # 5. Verify the note is displayed correctly after reload
            await expect(page.get_by_text(note_title)).to_be_visible()

            # Verify Markdown rendering
            await expect(page.get_by_role("heading", name="Heading 1")).to_be_visible()
            await expect(page.get_by_text("This is bold text.")).to_be_visible()
            await expect(page.get_by_text("This is italic.")).to_be_visible()
            await expect(page.get_by_text('print("Hello, World!")')).to_be_visible()
            print("Note content verified after reload.")

            # 6. Take a screenshot for visual confirmation
            screenshot_path = "jules-scratch/verification/verification.png"
            await page.screenshot(path=screenshot_path)
            print(f"Screenshot saved to {screenshot_path}")

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            await browser.close()

asyncio.run(main())