import yfinance as yf
import pandas as pd
import time

# Trading Parameters
SYMBOL = "MESH25.CME"  # Micro E-mini S&P 500 Futures
SHORT_MA = 5  # Short Moving Average
LONG_MA = 20  # Long Moving Average
TRADE_QUANTITY = 1  # Number of contracts per trade

# Paper Trading Account
balance = 2000  # Starting cash
position = 0  # Number of open contracts
entry_price = 0  # Price at which position was opened

def get_historical_data():
    """Fetches historical futures data from Yahoo Finance."""
    df = yf.download(SYMBOL, period="7d", interval="1h")  # Last 7 days, 1-hour candles
    df["Short_MA"] = df["Close"].rolling(SHORT_MA).mean()
    df["Long_MA"] = df["Close"].rolling(LONG_MA).mean()
    return df

def calculate_signal(df):
    """Determines buy/sell signals based on MA crossover."""
    if df["Short_MA"].iloc[-1] > df["Long_MA"].iloc[-1]:
        return "BUY"
    elif df["Short_MA"].iloc[-1] < df["Long_MA"].iloc[-1]:
        return "SELL"
    return "HOLD"

def execute_trade(action, price):
    """Simulates trade execution in paper trading."""
    global balance, position, entry_price

    if action == "BUY" and position == 0:
        position += TRADE_QUANTITY
        entry_price = price
        print(f"🟢 BUY {TRADE_QUANTITY} contracts at {price}")
    
    elif action == "SELL" and position > 0:
        profit = (price - entry_price) * position * 5  # Assuming $5 per point
        balance += profit
        position = 0
        print(f"🔴 SELL {TRADE_QUANTITY} contracts at {price} | PnL: ${profit:.2f}")

    print(f"💰 Balance: ${balance:.2f}, Position: {position}, Entry: {entry_price}")

def main():
    """Main trading loop."""
    while True:
        df = get_historical_data()
        if df is not None and not df.empty:
            action = calculate_signal(df)
            last_price = df["Close"].iloc[-1]
            execute_trade(action, last_price)
        else:
            print("⚠ No market data available.")

        time.sleep(20)

if __name__ == "__main__":
    main()
