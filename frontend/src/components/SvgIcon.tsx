import { FC, SVGProps } from 'react';

interface SvgIconProps extends SVGProps<SVGSVGElement> {
  name: string;
  path?: string;
  color?: string;
  size?: number | string;
  className?: string;
}

const SvgIcon: FC<SvgIconProps> = ({ name, path = '', color = 'currentColor', size = 24, className = '', ...props }) => {
  // Build symbolId based on path parameter
  const symbolId = path ? `#icon-${path}-${name}` : `#icon-${name}`;

  return (
    <svg className={`svg-icon ${className}`} style={{ width: `${size}px`, height: `${size}px` }} aria-hidden="true" {...props}>
      <use xlinkHref={symbolId} fill={color} />
    </svg>
  );
};

export default SvgIcon;
