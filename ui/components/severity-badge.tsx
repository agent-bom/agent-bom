import { severityColor } from "@/lib/api";

interface Props {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className = "" }: Props) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-mono font-semibold uppercase tracking-wide ${severityColor(severity)} ${className}`}
    >
      {severity}
    </span>
  );
}
