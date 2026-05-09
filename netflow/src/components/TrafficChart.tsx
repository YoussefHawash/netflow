import { useEffect, useRef } from "react";
import type { TrafficHistory } from "../lib/useMonitor";

type Props = { history: TrafficHistory };

export function TrafficChart({ history }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;

    const draw = () => {
      const surface = prepareCanvas(canvas);
      if (!surface) return;
      const { ctx, width, height } = surface;
      const maxValue =
        Math.max(12, ...history.received, ...history.sent) * 1.15;
      const padLeft = 34,
        padRight = 12,
        padTop = 12,
        padBottom = 28;
      const graphWidth = width - padLeft - padRight;
      const graphHeight = height - padTop - padBottom;

      ctx.clearRect(0, 0, width, height);
      drawGrid(
        ctx,
        width,
        height,
        padLeft,
        padRight,
        padTop,
        padBottom,
        maxValue,
        ["60s", "50s", "40s", "30s", "20s", "10s", "0s"],
      );
      drawLine(
        ctx,
        history.received,
        "#3fb950",
        maxValue,
        padLeft,
        padTop,
        graphWidth,
        graphHeight,
      );
      drawLine(
        ctx,
        history.sent,
        "#a78bfa",
        maxValue,
        padLeft,
        padTop,
        graphWidth,
        graphHeight,
      );
    };

    draw();
    window.addEventListener("resize", draw);
    return () => window.removeEventListener("resize", draw);
  }, [history]);

  return (
    <canvas
      ref={ref}
      className="block h-[full] w-full"
      width={520}
      height={240}
    />
  );
}

function prepareCanvas(canvas: HTMLCanvasElement) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const cssWidth = Math.max(1, Math.floor(rect.width));
  const cssHeight = Math.max(1, Math.floor(rect.height || canvas.height));
  const targetWidth = Math.round(cssWidth * dpr);
  const targetHeight = Math.round(cssHeight * dpr);
  if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
    canvas.width = targetWidth;
    canvas.height = targetHeight;
  }
  canvas.style.height = `${cssHeight}px`;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width: cssWidth, height: cssHeight };
}

function drawGrid(
  ctx: CanvasRenderingContext2D,
  width: number,
  height: number,
  padLeft: number,
  padRight: number,
  padTop: number,
  padBottom: number,
  maxValue: number,
  labels: string[],
) {
  const graphHeight = height - padTop - padBottom;
  const graphWidth = width - padLeft - padRight;

  ctx.strokeStyle = "#21262d";
  ctx.lineWidth = 0.5;
  ctx.fillStyle = "#484f58";
  ctx.font = "10px Segoe UI, sans-serif";
  ctx.textAlign = "right";

  for (let step = 0; step <= 6; step += 1) {
    const value = (maxValue / 6) * step;
    const y = padTop + graphHeight - (value / maxValue) * graphHeight;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(width - padRight, y);
    ctx.stroke();
    ctx.fillText(String(Math.round(value)), padLeft - 4, y + 3);
  }

  ctx.textAlign = "center";
  labels.forEach((label, i) => {
    const x = padLeft + (i / (labels.length - 1)) * graphWidth;
    ctx.fillText(label, x, height - 8);
  });
}

function drawLine(
  ctx: CanvasRenderingContext2D,
  data: number[],
  color: string,
  maxValue: number,
  padLeft: number,
  padTop: number,
  graphWidth: number,
  graphHeight: number,
) {
  const x = (i: number) => padLeft + (i / (data.length - 1)) * graphWidth;
  const y = (v: number) => padTop + graphHeight - (v / maxValue) * graphHeight;

  ctx.beginPath();
  data.forEach((value, i) => {
    if (i === 0) ctx.moveTo(x(i), y(value));
    else ctx.lineTo(x(i), y(value));
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.lineTo(x(data.length - 1), y(0));
  ctx.lineTo(x(0), y(0));
  ctx.closePath();
  const gradient = ctx.createLinearGradient(0, padTop, 0, padTop + graphHeight);
  gradient.addColorStop(0, `${color}40`);
  gradient.addColorStop(1, `${color}05`);
  ctx.fillStyle = gradient;
  ctx.fill();
}
