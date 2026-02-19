import React from "react";

/**
 * DashboardPanel
 *
 * PURPOSE:
 * - Enforces consistent sizing & spacing across the dashboard
 * - Prevents components from breaking layout
 * - Makes the DashboardPage the single source of layout truth
 *
 * RULES:
 * - Components render content ONLY
 * - Panel controls height, padding, overflow
 */

const DashboardPanel = ({
  title,
  subtitle,
  actions,
  children,
  height = "h-[320px]",
  className = "",
}) => {
  return (
    <div
      className={`
        bg-gray-800/90
        border border-gray-700
        rounded-xl
        shadow-lg
        flex flex-col
        ${height}
        ${className}
      `}
    >
      {/* Header */}
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700">
          <div>
            {title && (
              <h3 className="text-sm font-semibold text-gray-200 tracking-wide">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-xs text-gray-400 mt-0.5">
                {subtitle}
              </p>
            )}
          </div>

          {actions && (
            <div className="flex items-center gap-2">
              {actions}
            </div>
          )}
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-hidden p-3">
        {children}
      </div>
    </div>
  );
};

export default DashboardPanel;