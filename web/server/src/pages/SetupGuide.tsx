import { SetupGuideContent } from '../components/SetupGuide/SetupGuide'

export function SetupGuide() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h2 className="text-2xl font-bold text-white">Setup Guide</h2>
        <p className="text-bifrost-muted mt-1">
          Configure your system and applications to use the Bifrost proxy
        </p>
      </div>

      {/* Guide Content */}
      <SetupGuideContent />
    </div>
  )
}
