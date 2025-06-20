import sys
import os

# Proje kök dizinini path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from security_tool import SecurityTool
except ImportError as e:
    print(f"Import hatası: {e}")
    print("Mevcut Python path:", sys.path)
    raise

async def main():
    tool = SecurityTool()
    await tool.run()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
    