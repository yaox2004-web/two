import akshare as ak
import pandas as pd
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def main():
    today = datetime.now().strftime("%Y%m%d")
    print(f"开始拉取数据，日期: {today}")

    # 1. 拉取全市场A股实时快照
    print("正在拉取全市场行情...")
    df = ak.stock_zh_a_spot_em()
    df.to_parquet(DATA_DIR / f"spot_{today}.parquet", index=False)
    print(f"全市场快照完成，共 {len(df)} 只股票")

    # 2. 拉取上证指数日线历史
    print("正在拉取上证指数日线...")
    index_df = ak.index_zh_a_hist(symbol="000001", period="daily")
    index_df.to_parquet(DATA_DIR / "sh_index_daily.parquet", index=False)
    print(f"上证指数完成，共 {len(index_df)} 条记录")

    print("全部数据拉取完成！")

if __name__ == "__main__":
    main()
