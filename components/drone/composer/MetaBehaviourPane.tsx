import { SelfDestructConditions } from './meta/SelfDestructConditions';
import { SelfReferentialActions } from './meta/SelfReferentialActions';
import { InstanceManagement } from './meta/InstanceManagement';

export function MetaBehaviourPane() {
  return <div className="space-y-2"><SelfDestructConditions /><SelfReferentialActions /><InstanceManagement /></div>;
}
