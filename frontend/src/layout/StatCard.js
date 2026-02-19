import React from "react";

const statusColors = {
  low: "border-green-500 text-green-400",
  medium: "border-yellow-500 text-yellow-400",
  high: "border-red-500 text-red-400",
};

const StatCard = ({ title, value, subtitle, status = "low" }) => {
  return (
    <div
      className={`bg-gray-800 rounded-lg border-l-4 p-4 flex flex-col justify-center ${
        statusColors[status]
      }`}
    >
      <span className="text-xs uppercase tracking-wide text-gray-400">
        {title}
      </span>
      <span className="text-2xl font-bold">{value}</span>
      {subtitle && (
        <span className="text-xs text-gray-500 mt-1">{subtitle}</span>
      )}
    </div>
  );
};

export default StatCard;