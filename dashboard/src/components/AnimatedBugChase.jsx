
import React from 'react'

export default function AnimatedBugChase() {
  return (
    <div className="bug-chase-layer" aria-hidden="true">
      <div className="bug-path bug-path-one"><span className="dash-trail" /><span className="bug-runner">🐞</span><span className="bug-catcher">🕵️‍♂️</span></div>
      <div className="bug-path bug-path-two"><span className="dash-trail" /><span className="bug-runner">🐞</span><span className="bug-catcher">🕸️</span></div>
      <div className="radar-sweep" />
      <div className="floating-orb orb-a" />
      <div className="floating-orb orb-b" />
      <div className="floating-orb orb-c" />
    </div>
  )
}
