using System.Windows;
using Spemcs.Agent.UI.ViewModels;

namespace Spemcs.Agent.UI.Views;

public partial class SetupWizardWindow : Window
{
    public SetupWizardViewModel ViewModel { get; }

    public SetupWizardWindow(SetupWizardViewModel? viewModel = null)
    {
        InitializeComponent();
        ViewModel = viewModel ?? new SetupWizardViewModel();
        DataContext = ViewModel;

        ViewModel.OnRegistrationCompleted = () =>
        {
            DialogResult = true;
            Close();
        };

        Loaded += async (_, _) => await ViewModel.InitializeAsync();
    }
}
