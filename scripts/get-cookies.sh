#!/bin/bash
# Helper script to extract LinkedIn cookies from your browser
# and provide export commands for environment variables

set -e

echo "LinkedIn Cookie Extractor"
echo "========================="
echo ""

# Check for Chrome
CHROME_COOKIES="$HOME/Library/Application Support/Google/Chrome/Default/Cookies"
if [ -f "$CHROME_COOKIES" ]; then
    echo "Found Chrome cookies at: $CHROME_COOKIES"
    echo ""
    echo "To extract cookies from Chrome, you can use the Chrome DevTools:"
    echo "  1. Open LinkedIn.com in Chrome"
    echo "  2. Press F12 to open DevTools"
    echo "  3. Go to Application > Cookies > https://www.linkedin.com"
    echo "  4. Find these cookies and copy their values:"
    echo "     - li_at"
    echo "     - JSESSIONID"
    echo "     - lidc"
    echo ""
fi

# Check for Safari
SAFARI_COOKIES="$HOME/Library/Cookies/Cookies.binarycookies"
if [ -f "$SAFARI_COOKIES" ]; then
    echo "Found Safari cookies at: $SAFARI_COOKIES"
    echo ""
    echo "To extract cookies from Safari:"
    echo "  1. Open LinkedIn.com in Safari"
    echo "  2. Safari > Settings > Privacy > Manage Website Data"
    echo "  3. Search for 'linkedin.com'"
    echo "  Or use Safari's Web Inspector (Develop menu)"
    echo ""
fi

echo "Recommended: Use Chrome or Edge DevTools"
echo "=========================================="
echo ""
echo "1. Open https://www.linkedin.com in Chrome/Edge"
echo "2. Make sure you're logged in"
echo "3. Press F12 (or Cmd+Option+I on Mac)"
echo "4. Click 'Application' tab"
echo "5. Expand 'Cookies' in left sidebar"
echo "6. Click 'https://www.linkedin.com'"
echo "7. Find and copy the Value for these cookies:"
echo "   - li_at"
echo "   - JSESSIONID"
echo "   - lidc"
echo ""
echo "Then run these commands (with your actual values):"
echo ""
echo "export LINKEDIN_LI_AT=\"paste-li_at-value-here\""
echo "export LINKEDIN_JSESSIONID=\"paste-JSESSIONID-value-here\""
echo "export LINKEDIN_LIDC=\"paste-lidc-value-here\""
echo ""
echo "After setting these, run:"
echo "  ./bin/linkedin https://www.linkedin.com/in/YOUR-PROFILE/"
