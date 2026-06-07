import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def plot_metrics():
    print("Reading simulation_metrics.csv...")
    try:
        df = pd.read_csv("simulation_metrics.csv")
    except FileNotFoundError:
        print("Error: simulation_metrics.csv not found. Run performance_evaluator.py first.")
        return
    
    # Apply a clean academic seaborn theme (suitable for IEEE/academic papers)
    sns.set_theme(style="whitegrid")
    
    # Setup custom colors
    legacy_color = "#e74c3c" # Red
    ztcpp_color = "#2ecc71"  # Green
    palette = {"Legacy (TCP/TLS/App Auth)": legacy_color, "ZTCPP (Authenticated-before-Connect)": ztcpp_color}

    # ==========================================
    # 1. Throughput vs Latency Chart
    # ==========================================
    print("Generating Throughput vs Latency chart...")
    plt.figure(figsize=(10, 6))
    
    sns.scatterplot(
        data=df, 
        x="Throughput_req_sec", 
        y="Latency_ms", 
        hue="Architecture", 
        style="Architecture",
        palette=palette,
        s=120,
        alpha=0.8
    )
    
    plt.title("Signaling Storm: Throughput vs. Processing Latency", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Throughput (Requests / Second)", fontsize=12, fontweight='bold')
    plt.ylabel("Processing Latency (ms)", fontsize=12, fontweight='bold')
    
    # Optimize layout and save
    plt.legend(title="Architecture Framework", title_fontsize='11', fontsize='10', loc="upper left")
    plt.tight_layout()
    plt.savefig("throughput_vs_latency.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Saved -> throughput_vs_latency.png")

    # ==========================================
    # 2. Resource Footprint over time
    # ==========================================
    print("Generating CPU/RAM Footprint chart...")
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    # CPU Axis (Left)
    ax1.set_xlabel('Simulation Time Step', fontsize=12, fontweight='bold')
    ax1.set_ylabel('CPU Utilization (%)', color='#2c3e50', fontsize=12, fontweight='bold')
    
    sns.lineplot(
        data=df, 
        x="Time_Step", 
        y="CPU_Percent", 
        hue="Architecture", 
        ax=ax1, 
        linewidth=2.5, 
        palette=palette,
        legend=False
    )
    ax1.tick_params(axis='y', labelcolor='#2c3e50')
    ax1.set_ylim(0, 100)

    # RAM Axis (Right)
    ax2 = ax1.twinx()  
    ax2.set_ylabel('RAM Allocation (MB)', color='#8e44ad', fontsize=12, fontweight='bold')  
    
    # We use dashed lines for RAM to distinguish from CPU
    sns.lineplot(
        data=df, 
        x="Time_Step", 
        y="RAM_MB", 
        hue="Architecture", 
        ax=ax2, 
        linewidth=2.5, 
        linestyle="--", 
        palette=palette,
        legend=False
    )
    ax2.tick_params(axis='y', labelcolor='#8e44ad')
    
    plt.title("Signaling Storm Impact: Resource Exhaustion (CPU/RAM) Over Time", fontsize=14, fontweight='bold', pad=15)
    
    # Custom Legend
    import matplotlib.lines as mlines
    legacy_cpu = mlines.Line2D([], [], color=legacy_color, linestyle='-', label='Legacy CPU %')
    legacy_ram = mlines.Line2D([], [], color=legacy_color, linestyle='--', label='Legacy RAM MB')
    ztcpp_cpu = mlines.Line2D([], [], color=ztcpp_color, linestyle='-', label='ZTCPP CPU %')
    ztcpp_ram = mlines.Line2D([], [], color=ztcpp_color, linestyle='--', label='ZTCPP RAM MB')
    
    plt.legend(handles=[legacy_cpu, legacy_ram, ztcpp_cpu, ztcpp_ram], loc='upper left', fontsize=10)
    
    fig.tight_layout()  
    plt.savefig("resource_footprint.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Saved -> resource_footprint.png")
    
    print("All charts successfully generated!")

if __name__ == "__main__":
    plot_metrics()
