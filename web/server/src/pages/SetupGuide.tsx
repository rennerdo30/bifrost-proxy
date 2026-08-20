import { SetupGuideContent } from '../components/SetupGuide/SetupGuide'

export function SetupGuide() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h2 className="page-title">Setup Guide</h2>
        <p className="page-subtitle">
          Configure your system and applications to use the Bifrost proxy
        </p>
      </div>

      {/* Guide Content */}
      <SetupGuideContent />
    </div>
  )
}
