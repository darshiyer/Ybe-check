import React from 'react';
import './GlitchText.css';

interface GlitchTextProps {
    children: React.ReactNode;
    speed?: number;
    enableShadows?: boolean;
    enableOnHover?: boolean;
    className?: string;
}

const GlitchText: React.FC<GlitchTextProps> = ({
    children,
    speed = 1,
    enableShadows = true,
    enableOnHover = false,
    className = '',
}) => {
    const inlineStyles = {
        '--glitch-speed': `${speed}s`,
    } as React.CSSProperties;

    return (
        <div
            className={`glitch-container ${className} ${enableOnHover ? 'on-hover' : ''} ${enableShadows ? 'shadows' : ''}`}
            style={inlineStyles}
        >
            <span className="glitch-text-main">{children}</span>
            <span className="glitch-text-slice" aria-hidden="true">{children}</span>
            <span className="glitch-text-slice" aria-hidden="true">{children}</span>
        </div>
    );
};

export default GlitchText;
