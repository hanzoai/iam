"use client"

import * as React from "react"
import { CheckCircle, XCircle, AlertTriangle, Info, LucideIcon } from "lucide-react"
import { cn } from "../../lib/utils"
import { Button } from "./button"

type ResultStatus = "success" | "error" | "warning" | "info"

interface ResultCardProps extends React.HTMLAttributes<HTMLDivElement> {
  status: ResultStatus
  icon?: LucideIcon
  title: string
  subtitle?: string
  extra?: React.ReactNode
}

const statusConfig: Record<ResultStatus, { icon: LucideIcon; className: string }> = {
  success: { icon: CheckCircle, className: "text-emerald-400" },
  error: { icon: XCircle, className: "text-red-400" },
  warning: { icon: AlertTriangle, className: "text-amber-400" },
  info: { icon: Info, className: "text-blue-400" },
}

const ResultCard = React.forwardRef<HTMLDivElement, ResultCardProps>(
  ({ className, status, icon, title, subtitle, extra, children, ...props }, ref) => {
    const config = statusConfig[status]
    const Icon = icon || config.icon

    return (
      <div
        ref={ref}
        className={cn(
          "flex flex-col items-center justify-center rounded-lg border border-border bg-card p-8 text-center",
          className
        )}
        {...props}
      >
        <Icon className={cn("h-16 w-16 mb-4", config.className)} />
        <h3 className="text-xl font-semibold text-foreground mb-2">{title}</h3>
        {subtitle && (
          <p className="text-sm text-muted-foreground mb-6 max-w-md">{subtitle}</p>
        )}
        {extra && <div className="flex items-center gap-3 mb-4">{extra}</div>}
        {children}
      </div>
    )
  }
)
ResultCard.displayName = "ResultCard"

export { ResultCard, ResultCardProps, ResultStatus }
